# pqbit/pqbit/__init__.py

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

from .kyber import (
    kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

from .dilithium import (
    dilithium_keypair,
    dilithium_sign,
    dilithium_verify
)

from .falcon import (
    falcon_keypair,
    falcon_sign,
    falcon_verify
)

from .guardian import (
    calculate_entropy,
    measure_latency,
    select_best_peer,
    send_encrypted_broadcast,
    sign_node_identity,
    verify_peer_identity,
    run_guardian_audit
)

from .obfs4 import start_obfs4_proxy
from .wireguard import setup_wireguard_tunnel
from .pysocks import create_socks_proxy
from .pqclean import compile_pqclean, list_supported_algorithms

__all__ = [
    "kyber_keypair", "kyber_encapsulate", "kyber_decapsulate",
    "dilithium_keypair", "dilithium_sign", "dilithium_verify",
    "falcon_keypair", "falcon_sign", "falcon_verify",
    "calculate_entropy", "measure_latency", "select_best_peer",
    "send_encrypted_broadcast", "sign_node_identity", "verify_peer_identity", "run_guardian_audit",
    "start_obfs4_proxy", "setup_wireguard_tunnel", "create_socks_proxy",
    "compile_pqclean", "list_supported_algorithms"
]

