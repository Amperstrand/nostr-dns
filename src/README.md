# NOSTR DNS & CA - Proof of Concept

This directory contains the Python source code for a proof-of-concept system that uses the NOSTR protocol for decentralized DNS and as a self-sovereign certificate authority.

The core idea, as outlined in `notes.md`, is to use NOSTR events to map a NOSTR public key (`npub`) to an IP address and an associated SSL certificate. This allows for dynamic, censorship-resistant, and self-sovereign domain resolution and secure communication.

## Files and Status

Here is a breakdown of each Python file, its purpose, its current working status, and how it contributes to the proof-of-concept.

### `nostr_dns_lib.py`

- **Purpose**: This is the core library containing all the essential functions for interacting with the NOSTR network. It handles key generation, publishing IP address and certificate events (kinds 30000 and 30001), and fetching that information for a given `npub`.
- **Status**: **Working**. This library is stable and used by all other scripts.
- **PoC Aspect**: It directly implements the "Anchoring Trust via NOSTR Events" concept from `notes.md` by providing the fundamental building blocks for publishing and retrieving the necessary data from NOSTR relays.

### `update_ip_address.py`

- **Purpose**: A simple utility script that a server owner would run. It determines the public IP address of the machine and publishes it to a NOSTR relay, associated with the server's `npub`. It will create a new NOSTR identity (`/tmp/nsec.key`) on first run if one doesn't exist.
- **Status**: **Working**.
- **PoC Aspect**: This script is the first step for a user to participate in the system, demonstrating how a server announces its location.

### `fetch_ip_address.py`

- **Purpose**: A client-side utility to look up the IP address for a given `npub`. It queries the NOSTR relay for the latest IP address event published by that `npub`.
- **Status**: **Working**.
- **PoC Aspect**: This demonstrates the client-side resolution of an `npub` to an IP address, the most basic function of the decentralized DNS.

### `nostr_dns.py`

- **Purpose**: A full DNS server that listens for queries. When it receives a query for a `.nostr` domain (e.g., `my-npub.nostr`), it queries the NOSTR network for the corresponding IP address and returns it. It also fetches and caches the associated SSL certificate.
- **Status**: **Working**.
- **PoC Aspect**: This is the primary implementation of the decentralized DNS concept, showing how standard DNS queries can be resolved via NOSTR. It also supports the "Anchoring Trust" model by fetching the certificate needed for verification.

### `nostr_mdns.py`

- **Purpose**: An mDNS (multicast DNS) server that provides resolution for `.local` domains (e.g., `my-npub.local`). This is useful for local network testing without needing a public IP or reconfiguring the operating system's DNS settings.
- **Status**: **Working**.
- **PoC Aspect**: This provides a practical way to test the system in a local environment, as mentioned in the `notes.md` file for local testing scenarios.

### `https_demo_server.py`

- **Purpose**: A demonstration HTTPS server that uses a **standard, self-signed certificate**. It starts an HTTPS server on port 4443, generates a certificate, and then publishes that certificate to the NOSTR network. This allows clients and the DNS servers to fetch the "official" certificate for the `npub`.
- **Status**: **Working**.
- **PoC Aspect**: This demonstrates the server-side component of the "Anchoring Trust via NOSTR Events" model. It shows how a server can publish its own certificate for clients to discover and trust.

### `https_demo_server_alt.py`

- **Purpose**: An **experimental** HTTPS server that explores an alternative trust model. It generates a self-signed certificate where the key is the NOSTR private key itself (using the `secp256k1` curve). This allows a client to verify the certificate using only the server's known `npub`.
- **Status**: **Partially Working / Experimental**. The server runs, but modern TLS clients (like browsers and `curl` on macOS) often fail to connect because the `secp256k1` curve is not commonly supported in TLS 1.3 cipher suites. It may work with older clients or by forcing TLS 1.2, but it is not reliable.
- **PoC Aspect**: This is a proof-of-concept for the "NSEC-Issued SSL Certificates" idea from `notes.md`. It demonstrates the potential for a purely cryptographic trust model without a traditional CA, but also highlights the significant practical limitations with current TLS standards.

## How it All Works Together

This collection of scripts provides a complete, end-to-end demonstration of the NOSTR-based DNS and CA system.

1.  A server owner runs `https_demo_server.py` to start their service. This generates a self-signed certificate and publishes it to NOSTR.
2.  The server owner runs `update_ip_address.py` to publish their IP address to NOSTR.
3.  A client runs `nostr_dns.py` as their local DNS resolver.
4.  When the client tries to access `https://<npub>.nostr`, the `nostr_dns.py` server resolves the IP and verifies the server's certificate against the one published on NOSTR, establishing a trusted connection.

This setup demonstrates a fully decentralized, self-sovereign, and censorship-resistant method for domain resolution and secure communication.
