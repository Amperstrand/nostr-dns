# NIP-XYZ: Decentralized DNS and Certificate Authority over NOSTR (Draft)

## Draft Status
This NIP is a **draft** and subject to change. Feedback and discussion are encouraged.

## Summary
Defines a method for decentralized, self-sovereign DNS and certificate authority (CA) services using the NOSTR protocol. This enables dynamic mapping of hostnames to IP addresses and trust anchoring for certificates, leveraging NOSTR events and identities.

## Motivation
Traditional DNS and CA systems are centralized, creating single points of failure and trust. This NIP proposes a decentralized alternative, allowing users to:
- Anchor trust in their own NOSTR identities (npub/nsec)
- Dynamically map hostnames to IP addresses
- Enable secure HTTPS communication using self-signed certificates anchored in NOSTR events

## Event Kinds
- **Kind 30000**: IP Address Announcement
  - Content: `{ "ip": "<IPv4/IPv6 address>" }`
  - Published by the NOSTR identity (npub) controlling the service/host
- **Kind 30001** (optional): Certificate Announcement
  - Content: `{ "cert_pem": "<PEM-encoded certificate>" }`
  - Used to publish a self-signed certificate for the service

## Hostname Resolution
- Hostnames of the form `<npub>.nostr` are resolved by clients or local DNS proxies.
- To resolve `<npub>.nostr`, the client fetches the latest Kind 30000 event from `<npub>` and uses the announced IP address.
- If no event is found, the domain is considered non-existent (NXDOMAIN).

## Certificate Trust
- Optionally, a Kind 30001 event may be published by `<npub>` containing a PEM-encoded certificate.
- Clients may fetch and use this certificate for HTTPS connections to the resolved IP, anchoring trust in the NOSTR identity.

## Example Event (Kind 30000)
```json
{
  "kind": 30000,
  "pubkey": "<hex of npub>",
  "content": "{\"ip\":\"216.128.178.176\"}",
  "created_at": 1680000000,
  "tags": []
}
```

## Example Event (Kind 30001)
```json
{
  "kind": 30001,
  "pubkey": "<hex of npub>",
  "content": "{\"cert_pem\":\"-----BEGIN CERTIFICATE-----...\"}",
  "created_at": 1680000001,
  "tags": []
}
```

## Security Considerations
- Trust is anchored in the NOSTR keypair (npub/nsec). Compromise of the nsec allows DNS/IP/certificate hijacking for that identity.
- Clients should validate that events are signed by the expected npub.
- Certificate pinning and additional validation are recommended for sensitive use cases.

## Compatibility
- This NIP is compatible with any NOSTR relay and client capable of reading and publishing events of the specified kinds.
- DNS proxies and client resolvers must implement the event lookup logic for `.nostr` domains.

## Copyright
This NIP is released under the MIT License.
