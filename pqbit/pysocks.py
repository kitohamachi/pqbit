# pqbit/pqbit/pysocks.py

import socket
import socks  # type: ignore
import logging

logger = logging.getLogger("pqbit.pysocks")

# Preserve the original socket to allow restoration
_original_socket = socket.socket

def create_socks_proxy(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """
    Configures a SOCKS5 proxy using PySocks.

    Args:
        host (str): SOCKS5 proxy address
        port (int): SOCKS5 proxy port

    Returns:
        bool: True if configured successfully, False otherwise
    """
    if not isinstance(host, str):
        logger.error("Invalid host type for SOCKS5 proxy")
        return False
    if not isinstance(port, int) or port <= 0:
        logger.error("Invalid port for SOCKS5 proxy")
        return False

    try:
        socks.set_default_proxy(socks.SOCKS5, host, port)
        socket.socket = socks.socksocket  # type: ignore
        logger.info(f"SOCKS5 proxy configured on {host}:{port}")
        return True
    except Exception as e:
        logger.error(f"Failed to configure SOCKS5 proxy: {e}")
        return False

def reset_proxy() -> None:
    """
    Restores the system's default socket, disabling the SOCKS proxy.
    """
    socket.socket = _original_socket  # type: ignore
    logger.info("SOCKS5 proxy disabled and socket restored.")
