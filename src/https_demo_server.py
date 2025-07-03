"""
A simple HTTPS server with a self-signed certificate for proof of concept.
The certificate and key are generated and stored in /tmp.
"""
import asyncio
import http.server
import ssl
import os
import subprocess
from nostr_dns_lib import get_own_npub, publish_cert

CERT_FILE = "/tmp/nostr_demo_cert.pem"
KEY_FILE = "/tmp/nostr_demo_key.pem"
PORT = 4443
NSEC_FILE = "/tmp/nsec.key"

async def main():
    # Get npub to use in certificate
    try:
        npub = await get_own_npub()
        print(f"Found npub: {npub}, using it for certificate generation.")
    except FileNotFoundError:
        print(f"Error: {NSEC_FILE} not found. Please run update_ip_address.py first to generate a key.")
        return

    # Generate self-signed certificate if not present
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("Generating self-signed certificate in /tmp...")
        # The Common Name (CN) is limited to 64 chars. The npub is too long.
        # We use a short CN and put the full domain in the Subject Alternative Name (SAN).
        short_cn = npub[:16]
        san_list = f"DNS:{npub}.nostr,DNS:{npub}.local"
        subprocess.run([
            "openssl", "req", "-x509", "-nodes", "-days", "1",
            "-newkey", "rsa:2048",
            "-keyout", KEY_FILE,
            "-out", CERT_FILE,
            "-subj", f"/CN={short_cn}",
            "-addext", f"subjectAltName = {san_list}"
        ], check=True)

        # Publish the new certificate to Nostr
        with open(CERT_FILE, "r") as f:
            cert_pem = f.read()
        print("Publishing certificate to Nostr...")
        cert_event_id = await publish_cert(cert_pem)
        print(f"✅ Published certificate in event: {cert_event_id}")

    # Start the HTTPS server
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving HTTPS on port {PORT} for {npub}.nostr and {npub}.local...")
    httpd.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
