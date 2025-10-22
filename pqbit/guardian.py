# pqbit/pqbit/guardian.py

import logging
import time
import socket
from collections import Counter
from math import log2

from . import wireshark
from .falcon import falcon_keypair, falcon_sign, falcon_verify
from .kyber import kyber_encapsulate

logger = logging.getLogger("pqbit.guardian")

# -------------------------------
# 📊 Entropia de tráfego
# -------------------------------

def calculate_entropy(data: bytes) -> float:
    counter = Counter(data)
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((count / total) * log2(count / total) for count in counter.values())

# -------------------------------
# ⏱️ Medição de latência
# -------------------------------

def measure_latency(ip: str, port: int = 51820) -> float:
    start = time.time()
    try:
        sock = socket.create_connection((ip, port), timeout=1)
        sock.close()
        return time.time() - start
    except Exception:
        return float('inf')

# -------------------------------
# 🧠 Seleção de melhor peer
# -------------------------------

def select_best_peer(peers: list) -> list:
    scores = []
    for peer in peers:
        latency = measure_latency(peer["endpoint"].split(":")[0])
        entropy = calculate_entropy(peer.get("recent_data", b""))
        score = latency + (1 / (entropy + 0.01))  # menor latência + maior entropia
        scores.append((peer["name"], score))
    return sorted(scores, key=lambda x: x[1])

# -------------------------------
# 🛰️ Broadcast criptografado com Kyber1024
# -------------------------------

def send_encrypted_broadcast(message: str, peer_pk: bytes, port: int = 9999):
    ct, _ = kyber_encapsulate(peer_pk)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(ct, ('<broadcast>', port))
    logger.info(f"Encrypted broadcast sent to port {port}.")

# -------------------------------
# 🔐 Assinatura e verificação com Falcon1024
# -------------------------------

def sign_node_identity(node_name: str, private_key: bytes) -> bytes:
    return falcon_sign(node_name.encode(), private_key)

def verify_peer_identity(peer_name: str, signature: bytes, public_key: bytes) -> bool:
    return falcon_verify(peer_name.encode(), signature, public_key)

# -------------------------------
# 🛡️ Auditoria de tráfego com Wireshark
# -------------------------------

def run_guardian_audit(interface: str = "tun0", duration: int = 30):
    """
    Run a full traffic audit using the Bit512 Guardian.

    Args:
        interface (str): Network interface to capture traffic from.
        duration (int): Duration of the capture in seconds.

    Raises:
        TypeError: If interface is not a string.
        ValueError: If duration is not a positive integer.
    """
    if not isinstance(interface, str):
        raise TypeError("Interface must be a string.")
    if not isinstance(duration, int) or duration <= 0:
        raise ValueError("Duration must be a positive integer.")

    logger.info(f"Bit512 Guardian: starting audit on interface '{interface}' for {duration}s.")
    wireshark.audit(interface=interface, duration=duration)
    logger.info("Bit512 Guardian: audit completed.")
