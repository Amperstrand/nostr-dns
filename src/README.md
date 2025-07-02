# NOSTR DNS Proof of Concept

This is a demo proof of concept for a NOSTR Improvement Proposal (NIP) to create a self-sovereign alternative to Let's Encrypt and Dynamic DNS providers. It demonstrates decentralized DNS and trust anchoring using the NOSTR protocol.

## What is this?

- A local DNS server that resolves `.nostr` domains by looking up the latest IP address published by a NOSTR public key (npub) as a NOSTR event.
- All other DNS queries are proxied to a normal upstream DNS server (default: Google DNS 8.8.8.8).
- Intended as a foundation for a decentralized, user-controlled DNS and certificate authority system.

## How to Run

1. **Requirements:**
   - Python 3.8+
   - macOS (tested only on macOS for now)
   - Install Python dependencies:
     ```sh
     pip install -r requirements.txt
     ```
   - NOSTR dependencies (see `requirements.txt`)

2. **Start the DNS server:**
   ```sh
   python3 nostr_dns.py
   ```
   - On first run, you may be prompted for your password to create `/etc/resolver/nostr` (macOS only).
   - This will configure your system to resolve `.nostr` domains using the local DNS server on port 5354.

3. **Test it:**
   - After starting the server, you should be able to run:
     ```sh
     ping npub1gxfqkfaldasaztnsye3kjskk0nq57vfyra2a7xfjd8kpwx7dfheqvvfz7s.nostr
     ```
   - The DNS server will resolve the IP address for the given NOSTR public key if it has published an IP event.

## Notes

- Only tested on macOS. Windows and Linux users will need to manually set their DNS server to point to this script (on 127.0.0.1:53 or 127.0.0.1:5354).
- The server only knows how to look up `.nostr` TLDs; all other requests are proxied to an upstream DNS server.
- This is a proof of concept and not production-ready. Use at your own risk.

## Why?

- Demonstrates a decentralized, self-sovereign approach to DNS and certificate authority using NOSTR identities.
- Provides a foundation for further work on trustless, user-controlled internet infrastructure.

---

For more details, see the NIP draft and the code in this repository.
