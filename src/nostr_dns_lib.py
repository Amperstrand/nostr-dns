import os
import json
from typing import Optional
from electrum_aionostr.key import PrivateKey, PublicKey
from electrum_aionostr.event import Event
from electrum_aionostr.relay import Manager
import ssl
import socket
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

RELAY = "wss://relay.snort.social"
NSEC_FILE = "/tmp/nsec.key"

logger = logging.getLogger(__name__)

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
    logger.debug(f"Published event {event.id} to relay: {relay}")
    return event.id

def nsec_to_pem(nsec_file: str, pem_file: str):
    """Converts a Nostr private key (nsec) to a standard PEM file."""
    if not os.path.exists(nsec_file):
        raise FileNotFoundError(f"No NOSTR key found: {nsec_file}")
    with open(nsec_file, 'r') as f:
        nsec = f.read().strip()
    
    # Use the library to parse the nsec and get the raw private key bytes
    sk = PrivateKey.from_nsec(nsec)
    private_key_bytes = sk.raw_secret
    
    # Create an Elliptic Curve private key object from the raw bytes
    # The curve for Nostr is secp256k1
    private_value = int.from_bytes(private_key_bytes, 'big')
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())

    # Serialize the key to PEM format
    with open(pem_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

async def publish_cert(cert_pem: str, nsec_file: str = NSEC_FILE, relay: str = RELAY) -> str:
    """Publishes a PEM certificate to a Nostr relay."""
    if not os.path.exists(nsec_file):
        raise FileNotFoundError(f"No NOSTR key found: {nsec_file}")
    with open(nsec_file) as f:
        sk = PrivateKey.from_nsec(f.read().strip())

    event = Event(
        content=cert_pem,
        pubkey=sk.public_key.hex(),
        kind=30001,
        tags=[]
    )
    event.sign(sk.hex())
    manager = Manager([relay])
    await manager.connect()
    await manager.add_event(event)
    await manager.close()
    logger.info(f"Published certificate event {event.id} to relay: {relay}")
    return event.id

def get_ssl_certificate(hostname, ip_address, port=443):
    """
    Fetches the SSL certificate in PEM format from a given IP address and port.
    Tries port 443 first, then 4443 as a failover if 443 fails.
    """
    context = ssl.create_default_context()
    # We don't verify here, because we are fetching a self-signed cert.
    # The verification happens by comparing it to the one from Nostr.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    for try_port in (port, 4443) if port == 443 else (port,):
        try:
            with socket.create_connection((ip_address, try_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if not cert_der:
                        logger.warning(f"No certificate received from {hostname} ({ip_address}:{try_port})")
                        continue
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    logger.info(f"Successfully fetched SSL certificate for {hostname} ({ip_address}:{try_port})")
                    return cert_pem
        except socket.timeout:
            logger.warning(f"Timeout connecting to {ip_address}:{try_port} for SSL certificate.")
        except ssl.SSLError as e:
            # This can happen with self-signed certs if not handled correctly
            logger.warning(f"SSL error for {hostname} ({ip_address}:{try_port}): {e}")
        except ConnectionRefusedError:
            logger.warning(f"Connection refused by {ip_address}:{try_port} when fetching SSL certificate.")
        except Exception as e:
            logger.error(f"Could not fetch SSL certificate from {hostname} ({ip_address}:{try_port}): {e}")
    return None

async def fetch_cert(npub_bech32: str, relay: str = RELAY) -> Optional[str]:
    """Fetches the latest PEM certificate from a Nostr relay for a given npub."""
    pub_hex = PublicKey.from_npub(npub_bech32).hex()
    manager = Manager([relay])
    await manager.connect()
    filt = {"authors": [pub_hex], "kinds": [30001], "limit": 1}
    sub_id = "fetch_cert"
    queue = await manager.subscribe(sub_id, filt)
    cert_pem = None
    try:
        event = await queue.get()
        if event:
            cert_pem = event.content
            logger.info(f"Fetched certificate for {npub_bech32} from event {event.id}")
    finally:
        await manager.close()
    return cert_pem

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
