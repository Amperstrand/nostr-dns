# NOSTR DNS & Self-Sovereign CA: Implementation Notes

## SSL Certificate Handling (Future Work)

- **NSEC-Issued SSL Certificates:**
  - Generate an SSL certificate using the NOSTR private key (nsec).
  - The certificate is self-signed and can be verified by clients using the corresponding npub.
  - Trust model: The client adds the certificate to a local trusted list.
  - Limitation: Only works with SSL 1.2 (not 1.3) due to cipher/curve restrictions.
  - For local testing, the certificate could be valid for `$npub.local` and mapped in `/etc/hosts`.

- **Anchoring Trust via NOSTR Events:**
  - Publish the self-signed certificate and current IP as NOSTR events.
  - Clients (or the DNS server) fetch and verify the certificate from NOSTR events.
  - The DNS server could, just-in-time, add the self-signed certificate to the system/user trust store, enabling browsers to trust `https://$npub.nostr`.
  - This would allow seamless HTTPS access in any browser, provided the trust store is updated.
  - Needs careful handling for security and cross-platform compatibility.

## Subdomain Support (TODO)

- Add support for subdomains, e.g. `https://www.$npub.nostr`.
  - The DNS server should parse and resolve subdomains, mapping them to the same IP as `$npub.nostr` or allowing custom mapping via NOSTR events.
  - Consider standardizing the event format to support subdomain records.

## Other Ideas / TODOs

- Standardize the NOSTR event kind and tags for IP and certificate announcements.
- Add Linux and Windows support for automatic DNS configuration.
- Add a utility to generate and publish SSL certificates as NOSTR events.
- Explore integration with browser extensions for dynamic trust store updates.
- Document security considerations for trusting self-signed certificates from NOSTR events.

---

For more details, see `nostr-dns-ca.md` and the main codebase.
