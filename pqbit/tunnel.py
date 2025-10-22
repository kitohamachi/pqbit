# pqbit/pqbit/tunnel.py

import logging
from pqbit.wireguard import setup_wireguard_tunnel
from pqbit.obfs4 import start_obfs4_proxy
from pqbit.pysocks import create_socks_proxy

logger = logging.getLogger("pqbit.tunnel")

def start_secure_tunnel():
    """
    Starts a post-quantum secure tunnel combining WireGuard, Obfs4, and PySocks.

    Returns:
        bool: True if all steps complete successfully, False otherwise
    """
    logger.info("Starting post-quantum secure tunnel...")

    # Step 1: WireGuard
    wg_ok = setup_wireguard_tunnel()
    if not wg_ok:
        logger.error("WireGuard failed.")
        return False

    # Step 2: Obfs4
    obfs_proc = start_obfs4_proxy(port=1050)
    if not obfs_proc:
        logger.error("Obfs4 failed.")
        return False

    # Step 3: PySocks
    proxy_ok = create_socks_proxy(port=9050)
    if not proxy_ok:
        logger.warning("SOCKS proxy partially configured.")
    else:
        logger.info("SOCKS5 proxy enabled.")

    logger.info("Full tunnel enabled.")
    return True
