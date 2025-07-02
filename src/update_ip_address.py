import sys
import asyncio
from nostr_dns_lib import publish_ip, get_own_npub

DEFAULT_IP = "216.128.178.176"
NSEC_FILE = "/tmp/nsec.key"
RELAY = "wss://relay.snort.social"

async def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IP
    npub = await publish_ip(ip, nsec_file=NSEC_FILE, relay=RELAY)
    print(f"✅ Published IP {ip} for {npub}")

if __name__ == "__main__":
    asyncio.run(main())
