# fetch_ip_address.py (uses nostr_dns_lib, /tmp/nsec.key)
import sys
import asyncio
from nostr_dns_lib import fetch_ip, get_own_npub

RELAY = "wss://relay.snort.social"
NSEC_FILE = "/tmp/nsec.key"


async def main():
    if len(sys.argv) == 2:
        npub = sys.argv[1]
    else:
        npub = await get_own_npub(nsec_file=NSEC_FILE)
    ip = await fetch_ip(npub, relay=RELAY)
    if ip:
        print(f"✅ IP for {npub}: {ip}")
    else:
        print(f"❌ No IP announcement found for {npub}")


if __name__ == "__main__":
    asyncio.run(main())
