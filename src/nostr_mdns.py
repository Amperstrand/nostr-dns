import socket
import struct
import asyncio
import logging
from nostr_dns_lib import fetch_ip, get_ssl_certificate, fetch_cert

MCAST_GRP = '224.0.0.251'
MCAST_PORT = 5353
TTL = 255

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger("nostr_mdns")

class NostrMDNSResponder:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Not available on all systems
        self.sock.bind(("", MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)
        self.sock.setblocking(False)

    async def serve(self):
        logger.info(f"NOSTR mDNS responder running on UDP {MCAST_GRP}:{MCAST_PORT}...")
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, 1024)
            domain = self.get_domain(data)
            logger.info(f"Received mDNS query for domain: {domain} from {addr}")
            if domain and domain.endswith('.local.'):
                npub = domain[:-7]  # strip .local.
                if npub.startswith('npub1') and len(npub) >= 63:
                    try:
                        ip = await fetch_ip(npub)
                        if ip:
                            logger.info(f"Resolved {domain} to {ip} via NOSTR event")
                            response = self.build_response(data, ip)
                            self.sock.sendto(response, addr)

                            # --- Certificate Verification Logic ---
                            try:
                                # 1. Fetch the certificate published on Nostr
                                published_cert_pem = await fetch_cert(npub)
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
                                        else:
                                            logger.error(f"ERROR: Server certificate at {ip} does NOT match the one published on Nostr for {npub}.")
                            except Exception as e:
                                logger.error(f"An error occurred during certificate verification for {npub}: {e}")
                            # --- End Certificate Verification ---

                        else:
                            logger.info(f"No IP event found for {npub}")
                    except Exception as e:
                        logger.warning(f"Failed to resolve {npub}: {e}")
                else:
                    logger.info(f"Ignoring non-npub .local query: {domain}")

    def get_domain(self, data):
        # Parse the domain from the DNS query (same as nostr_dns.py)
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
        # Minimal mDNS response for A record
        transaction_id = query[:2]
        flags = b'\x84\x00'  # response, authoritative answer
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

if __name__ == "__main__":
    responder = NostrMDNSResponder()
    asyncio.run(responder.serve())
