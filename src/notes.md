# NOSTR DNS & Self-Sovereign CA: Implementation Notes

## Current Status (Implemented)

- **Decentralized DNS Resolution**: `nostr_dns.py` and `nostr_mdns.py` successfully resolve `.nostr` and `.local` domains to IP addresses by fetching the latest kind 30000 event from the corresponding `npub`.
- **Self-Signed Certificate Generation**: `https_demo_server.py` generates a self-signed SSL certificate that is valid for both `$npub.nostr` and `$npub.local` hostnames using the Subject Alternative Name (SAN) field.
- **Trust Anchoring via NOSTR Events**: The demo HTTPS server publishes its self-signed certificate as a kind 30001 event to a NOSTR relay.
- **End-to-End Certificate Verification**: The DNS/mDNS servers perform verification:
  1.  Fetch the IP from the kind 30000 event.
  2.  Fetch the authoritative PEM certificate from the kind 30001 event.
  3.  Connect to the server at the resolved IP and retrieve the certificate it is serving.
  4.  Compare the two certificates. If they match, trust is established.
- **Verified Certificate Caching for `curl`**: Upon successful verification, the DNS server saves the verified certificate to `/tmp/nostr-dns-<npub>.pem`. This allows tools like `curl` to make secure, trusted connections using the `--cacert` flag, pinning trust to the certificate verified via Nostr.

## Future Work & Ideas

- **Seamless Browser Integration**: The current model requires manual trust via `curl`'s `--cacert` flag or ignoring browser warnings. This is the biggest hurdle to adoption. A major next step is to find a way for browsers to resolve and trust `.nostr` domains automatically. Here are several potential models:

  - **Model A: The "Nostr Companion" Browser Extension/App (Most Feasible)**
    - A user installs a browser extension or a helper application.
    - This "Companion" would perform both DNS resolution and certificate validation.
    - **DNS:** It would intercept requests for `.nostr` domains and resolve them by querying Nostr relays for kind 30000 events.
    - **Trust:** When connecting to a `.nostr` site, it would fetch the authoritative certificate from the corresponding kind 30001 event. It would then compare this to the certificate presented by the server. If they match, it would signal to the browser that the connection is secure. This is similar to how some browsers integrate with decentralized protocols like IPFS.

  - **Model B: The "Nostr CA" Hybrid Model**
    - A public Certificate Authority could be established to issue certificates for `.nostr` domains.
    - **Validation:** Instead of traditional domain validation, this CA would validate ownership by issuing a cryptographic challenge that must be answered by publishing a signed Nostr event from the npub in question.
    - **The Trust Hurdle:** For this to be truly seamless, this new CA's root certificate would need to be accepted into the main browser root programs (Mozilla, Google, etc.), which is a very long and difficult process.
    - **Decentralized Evolution:** As you noted, a single CA is a central point of failure. This model could evolve into a "web of trust" where users can configure their clients to trust multiple CAs of their choice. A server could then present a certificate from any of these CAs.
    - **Name Constraints:** To reduce the risk of a compromised CA, its root certificate could use X.509 Name Constraints to restrict it to only issuing for the `*.nostr` TLD. This would make it much safer for users to install manually.

  - **Model C: The Local Proxy**
    - A background application acts as a local web proxy.
    - The user configures their OS or browser to route traffic through it.
    - The proxy would handle all the Nostr-specific logic: DNS resolution, fetching the cert from Nostr, and verifying it. It would then pass the traffic to the browser, potentially re-signing it with a locally trusted development certificate to create a seamless experience.

  - **Model D: The Pragmatic Hybrid Subdomain Model**
    - A service provider (e.g., `mynostrddns.com`) offers to issue standard, trusted SSL certificates for subdomains.
    - A user with `npub1...` would get a certificate for `$npub.mynostrddns.com`.
    - **The Key:** The certificate is generated with two Subject Alternative Names (SANs): `$npub.mynostrddns.com` and `$npub.nostr`.
    - **Result:**
      - **Unmodified Browsers:** A user visiting `https://$npub.mynostrddns.com` gets a valid HTTPS connection because the certificate is signed by a trusted authority like Let's Encrypt.
      - **Nostr-aware Clients:** A user visiting `https://$npub.nostr` can use the existing Nostr-based verification (Kind 30001 event) to validate the exact same certificate, achieving a trusted connection in a decentralized way.
    - This provides a parallel, interoperable path for both legacy and Nostr-native systems.

- **Subdomain Support**:
  - Add support for subdomains, e.g. `https://www.$npub.nostr`.
  - The DNS server should parse and resolve subdomains, mapping them to the same IP as `$npub.nostr` or allowing custom mapping via NOSTR events.
  - Consider standardizing the event format to support subdomain records.

- **Multiple IP Addresses per npub**:
  - An npub could publish multiple IP addresses. The DNS server could be made smarter about which IP to return based on the client's network or other hints.
  - The event format could include tags or metadata to help the DNS server select the appropriate IP.

- **Privacy Considerations**:
  - Publishing a public IP linked to a main `npub` may have privacy implications.
  - Users could be encouraged to use dedicated `npub`s for DNS/CA purposes.

- **Cross-Platform Support**:
  - Add Linux and Windows support for automatic DNS configuration.

- **Security Hardening**:
  - Document security considerations for trusting self-signed certificates from NOSTR events in more detail.
  - Explore certificate revocation mechanisms using Nostr.

---

For more details, see the NIP draft and the main codebase.

# Alternative secp256k1 Certificate Generation

- **Alternative: Direct secp256k1 Certificate (Port 4444)**: `https_demo_server_alt.py` generates a self-signed certificate using the Nostr private key and the secp256k1 curve. This certificate is not published to Nostr, but is cryptographically linked to the npub.

## Findings and Limitations

This approach, while cryptographically elegant, faces significant practical challenges with current TLS client implementations.

1.  **TLS 1.2 is Mandatory**: Most clients (including `curl`, `wget`, and browsers) do not support `secp256k1` certificates under TLS 1.3. The connection **must** be forced to use TLS 1.2.

2.  **Handshake Failures are Common**: Even when forcing TLS 1.2 and a compatible `ECDSA` cipher suite, the TLS handshake still fails with both `curl` (using LibreSSL) and `wget` (using GnuTLS/OpenSSL). This indicates a fundamental incompatibility or lack of support for `secp256k1` as a *certificate public key algorithm* in these common libraries, even when they support it for the key exchange part of the handshake.

**Conclusion**: This alternative trust model is currently not viable for general-purpose use with standard command-line tools or web browsers. It remains a valuable area for future research, but is blocked by the state of mainstream TLS client libraries. The primary, Nostr-verified certificate model (using a standard key type) remains the only practical solution.
