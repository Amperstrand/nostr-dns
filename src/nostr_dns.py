import socketserver
import socket
import threading
import sys
import os
import platform
import subprocess
import asyncio
import logging
from dnslib import DNSHeader, RR, A, DNSRecord, DNSQuestion, QTYPE
from dnslib.server import DNSServer, DNSLogger
from nostr_dns_lib import fetch_ip, get_ssl_certificate, fetch_cert

UPSTREAM_DNS = ('8.8.8.8', 53)  # Google DNS, change as needed
LOCAL_IP = '127.0.0.1'  # Default IP address for proof of concept

# Detect macOS and set port
IS_MAC = platform.system() == 'Darwin'
PORT = 5354 if IS_MAC else 53

# macOS resolver config
RESOLVER_PATH = '/etc/resolver/nostr'
RESOLVER_DIR = '/etc/resolver'
RESOLVER_CONTENT = 'nameserver 127.0.0.1\nport 5354\n'

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger("nostr_dns")

NSEC_FILE = "/tmp/nsec.key"

def write_with_macos_prompt(filepath, content):
    # Ensure /etc/resolver exists first
    if not os.path.exists(RESOLVER_DIR):
        script_mkdir = f'do shell script "mkdir -p {RESOLVER_DIR}" with administrator privileges'
        result = subprocess.run(['osascript', '-e', script_mkdir])
        if result.returncode != 0:
            logger.error(f"Failed to create directory {RESOLVER_DIR}.")
            sys.exit(1)
    # Now write the file
    script = f'do shell script "echo {content!r} | tee {filepath}" with administrator privileges'
    result = subprocess.run(['osascript', '-e', script])
    if result.returncode == 0:
        logger.info(f"Created/updated {filepath} using macOS system prompt.")
    else:
        logger.error(f"Failed to create/update {filepath}.")
        sys.exit(1)

def check_mac_resolver():
    if not IS_MAC:
        return
    needs_write = False
    if not os.path.exists(RESOLVER_PATH):
        needs_write = True
    else:
        with open(RESOLVER_PATH, 'r') as f:
            content = f.read()
            if content.strip() != RESOLVER_CONTENT.strip():
                needs_write = True
    if needs_write:
        logger.info(f"/etc/resolver/nostr is missing or incorrect. It should contain:\n{RESOLVER_CONTENT}")
        resp = input("Do you want to create/update it now? (y/N): ").strip().lower()
        if resp == 'y':
            write_with_macos_prompt(RESOLVER_PATH, RESOLVER_CONTENT)
        else:
            logger.warning("Not creating resolver file. DNS for .nostr will not work on macOS.")
            sys.exit(1)

# Simple cache for mocked SSL certificate fetches
ssl_cert_cache = set()

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        domain = self.get_domain(data)
        logger.info(f"Received DNS query for domain: {domain}")
        if domain and domain.endswith('.nostr.'):
            npub = domain[:-7]  # strip .nostr.
            try:
                ip = asyncio.run(fetch_ip(npub))
            except TypeError as e:
                logger.warning(f"No valid npub or no IP event found for {npub}: {e}")
                ip = None
            except Exception as e:
                logger.error(f"Unexpected error fetching IP for {npub}: {e}")
                ip = None
            if not ip:
                logger.info(f"Returning NXDOMAIN for {domain} (no IP event found or invalid npub)")
                response = self.build_nxdomain_response(data)
            else:
                logger.info(f"Resolved {domain} to {ip} via NOSTR event")
                response = self.build_response(data, ip)

                # --- Certificate Verification Logic ---
                try:
                    # 1. Fetch the certificate published on Nostr
                    published_cert_pem = asyncio.run(fetch_cert(npub))
                    if not published_cert_pem:
                        logger.warning(f"No certificate found on Nostr for {npub}")
                    else:
                        logger.info(f"Found certificate on Nostr for {npub}")

                        # 2. Fetch the certificate from the server
                        served_cert_pem = get_ssl_certificate(domain, ip)

                        if not served_cert_pem:
                            logger.warning(f"Could not fetch SSL certificate from server at {ip}")
                        else:
                            # 3. Compare the certificates
                            if published_cert_pem.strip() == served_cert_pem.strip():
                                logger.info(f"SUCCESS: Server certificate at {ip} matches the one published on Nostr for {npub}.")
                                # 4. Save the verified certificate for curl
                                cert_path = f"/tmp/nostr-dns-{npub}.pem"
                                with open(cert_path, "w") as f:
                                    f.write(served_cert_pem)
                                logger.info(f"Saved verified certificate to {cert_path}")
                            else:
                                logger.error(f"ERROR: Server certificate at {ip} does NOT match the one published on Nostr for {npub}.")
                except Exception as e:
                    logger.error(f"An error occurred during certificate verification for {npub}: {e}")
                # --- End Certificate Verification ---

            sock.sendto(response, self.client_address)
        else:
            logger.info(f"Proxying DNS query for {domain} to upstream DNS")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.sendto(data, UPSTREAM_DNS)
                resp, _ = upstream.recvfrom(512)
                sock.sendto(resp, self.client_address)

    def get_domain(self, data):
        # Parse the domain from the DNS query
        try:
            qlen = data[12]
            domain = ''
            i = 12
            while True:
                length = data[i]
                if length == 0:
                    break
                domain += data[i+1:i+1+length].decode() + '.'
                i += length + 1
            return domain
        except Exception:
            return None

    def build_response(self, query, ip):
        # Minimal DNS response for A record
        transaction_id = query[:2]
        flags = b'\x81\x80'
        qdcount = b'\x00\x01'
        ancount = b'\x00\x01'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        header = transaction_id + flags + qdcount + ancount + nscount + arcount
        question = query[12:]
        answer = b'\xc0\x0c'  # pointer to domain name
        answer += b'\x00\x01'  # type A
        answer += b'\x00\x01'  # class IN
        answer += b'\x00\x00\x00\x3c'  # TTL 60s
        answer += b'\x00\x04'  # data length
        answer += socket.inet_aton(ip)
        return header + question + answer

    def build_nxdomain_response(self, query):
        # Return a DNS response with RCODE=3 (Name Error / NXDOMAIN)
        transaction_id = query[:2]
        flags = b'\x81\x83'  # Standard query response, recursion available, RCODE=3
        qdcount = b'\x00\x01'
        ancount = b'\x00\x00'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        header = transaction_id + flags + qdcount + ancount + nscount + arcount
        question = query[12:]
        return header + question

if __name__ == '__main__':
    check_mac_resolver()
    with socketserver.UDPServer(('0.0.0.0', PORT), DNSHandler) as server:
        logger.info(f'NOSTR DNS running on UDP port {PORT}...')
        server.serve_forever()
