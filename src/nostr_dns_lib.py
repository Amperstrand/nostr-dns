import os
import json
from typing import Optional
from electrum_aionostr.key import PrivateKey, PublicKey
from electrum_aionostr.event import Event
from electrum_aionostr.relay import Manager

RELAY = "wss://relay.snort.social"
NSEC_FILE = "/tmp/nsec.key"

async def get_own_npub(nsec_file: str = NSEC_FILE) -> str:
    if not os.path.exists(nsec_file):
        raise FileNotFoundError(f"No NOSTR key found: {nsec_file}. Run update_ip_address.py first.")
    with open(nsec_file) as f:
        nsec = f.read().strip()
    sk = PrivateKey.from_nsec(nsec)
    return sk.public_key.bech32()

async def publish_ip(ip: str, nsec_file: str = NSEC_FILE, relay: str = RELAY) -> str:
    if not os.path.exists(nsec_file):
        sk = PrivateKey()
        with open(nsec_file, "w") as f:
            f.write(sk.bech32())
    else:
        with open(nsec_file) as f:
            sk = PrivateKey.from_nsec(f.read().strip())
    event = Event(
        content=json.dumps({"ip": ip}),
        pubkey=sk.public_key.hex(),
        kind=30000,
        tags=[]
    )
    event.sign(sk.hex())
    manager = Manager([relay])
    await manager.connect()
    await manager.add_event(event)
    await manager.close()
    return sk.public_key.bech32()

async def fetch_ip(npub_bech32: str, relay: str = RELAY) -> Optional[str]:
    pub_hex = PublicKey.from_npub(npub_bech32).hex()
    manager = Manager([relay])
    await manager.connect()
    filt = {"authors": [pub_hex], "kinds": [30000], "limit": 1}
    sub_id = "fetch_ip"
    queue = await manager.subscribe(sub_id, filt)
    try:
        while True:
            event = await queue.get()
            if event is None:
                break
            try:
                data = json.loads(event.content)
                ip = data.get("ip")
                if ip:
                    return ip
            except Exception:
                continue
    finally:
        await manager.close()
    return None
