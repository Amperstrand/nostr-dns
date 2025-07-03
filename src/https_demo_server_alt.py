"""
An alternative simple HTTPS server that generates a self-signed certificate
using the secp256k1 curve, the same curve used by Nostr.
The certificate is signed directly by the Nostr private key.
"""
import asyncio
import http.server
import ssl
import os
import subprocess
from nostr_dns_lib import get_own_npub, nsec_to_pem

CERT_FILE_ALT = "/tmp/nostr_demo_cert_alt.pem"
KEY_FILE_ALT_PEM = "/tmp/nostr_demo_key_alt.pem"
PORT = 4444
NSEC_FILE = "/tmp/nsec.key"

async def main():
    # Get npub to use in certificate
    try:
        npub = await get_own_npub()
        print(f"Found npub: {npub}, using its key to sign the certificate.")
    except FileNotFoundError:
        print(f"Error: {NSEC_FILE} not found. Please run update_ip_address.py first to generate a key.")
        return

    # Generate a secp256k1 private key in PEM format from the nsec
    print(f"Converting {NSEC_FILE} to PEM format for openssl...")
    nsec_to_pem(NSEC_FILE, KEY_FILE_ALT_PEM)
    print(f"Private key saved to {KEY_FILE_ALT_PEM}")

    # Generate self-signed certificate using the Nostr key
    if not os.path.exists(CERT_FILE_ALT):
        print("Generating secp256k1 self-signed certificate...")
        # Use a short CN and put the full domain in SAN, as before
        short_cn = npub[:16]
        san_list = f"DNS:{npub}.nostr,DNS:{npub}.local"
        
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-key", KEY_FILE_ALT_PEM,
            "-out", CERT_FILE_ALT,
            "-days", "1",
            "-subj", f"/CN={short_cn}",
            "-addext", f"subjectAltName = {san_list}"
        ], check=True)
        print(f"✅ Certificate generated and saved to {CERT_FILE_ALT}")

    # Print verification and usage instructions every time
    print("\n--- Verification & Usage ---")
    print("To verify this certificate against the npub, use the following steps:")
    print(f"1. Extract the public key from the certificate:")
    print(f"   openssl x509 -in {CERT_FILE_ALT} -pubkey -noout > /tmp/pubkey_from_cert.pem")
    print(f"2. Get the expected npub from your key file:")
    # Correctly escape the quotes for the inner command
    py_command = f"from nostr_dns_lib import get_own_npub; import asyncio; print(asyncio.run(get_own_npub('{NSEC_FILE}')))"
    print(f"   python3 -c '{py_command}'")
    print(f"3. The public key in the certificate must correspond to the npub.")
    print("\nTo connect with curl (NOTE: Forcing TLS 1.2 and a specific cipher suite):")
    print(f"   curl -v --tls-max 1.2 --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 --cacert {CERT_FILE_ALT} --resolve {npub}.nostr:{PORT}:127.0.0.1 https://{npub}.nostr:{PORT}")

    # Start the HTTPS server
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # To support secp256k1 certificates, many clients like curl require TLS 1.2.
    # We'll force the server to use only TLS 1.2 to increase compatibility.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    # Force a specific cipher suite that is compatible with ECDSA keys.
    # This is a debugging step to see if the issue is cipher negotiation.
    cipher = 'ECDHE-ECDSA-AES128-GCM-SHA256'
    context.set_ciphers(cipher)
    context.load_cert_chain(certfile=CERT_FILE_ALT, keyfile=KEY_FILE_ALT_PEM)
    
    print("\n--- Server SSL/TLS Debug Info ---")
    print(f"Server is configured for TLS 1.2 only.")
    print(f"Forcing cipher: {cipher}")

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"\nServing HTTPS on port {PORT} with a certificate signed by the Nostr key (TLS 1.2 only)...")
    httpd.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
