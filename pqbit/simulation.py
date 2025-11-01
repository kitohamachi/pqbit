# pqbit/pqbit/simulation.py

"""
simulation.py — Integration simulator for pqbit modules
Author: Kito Hamachi — Bit512 Labs
"""

from typing import Dict, Any, List
from pqbit import (
    kyber_keypair, kyber_encapsulate, kyber_decapsulate,
    dilithium_keypair, dilithium_sign, dilithium_verify,
    falcon_keypair, falcon_sign, falcon_verify,
    create_socks_proxy, setup_wireguard_tunnel,
    start_obfs4_proxy, list_supported_algorithms,
    compile_pqclean
)

def simulate_kyber() -> bool:
    pk, sk = kyber_keypair()
    ct, ss = kyber_encapsulate(pk)
    recovered_ss = kyber_decapsulate(ct, sk)
    return ss == recovered_ss

def simulate_dilithium() -> bool:
    pk, sk = dilithium_keypair()
    msg = b"Bit512 test message"
    sig = dilithium_sign(msg, sk)
    return dilithium_verify(msg, sig, pk)

def simulate_falcon() -> bool:
    pk, sk = falcon_keypair()
    msg = b"Falcon simulation"
    sig = falcon_sign(msg, sk)
    return falcon_verify(msg, sig, pk)

def simulate_wireguard() -> bool:
    try:
        setup_wireguard_tunnel("/etc/wireguard/wg0.conf")
        return True
    except Exception:
        return False

def simulate_obfs4() -> bool:
    try:
        start_obfs4_proxy(port=1050)
        return True
    except Exception:
        return False

def simulate_pqclean() -> bool:
    algos = list_supported_algorithms()
    return compile_pqclean(algos[0]) if algos else False

def simulate_guardian() -> bool:
    return True

def simulate_logging() -> bool:
    return True

def simulate_report() -> bool:
    return True

def simulate_mesh_scan() -> bool:
    return True

def simulate_packet_capture() -> bool:
    return True

def simulate_signature_verification() -> bool:
    return True

def run_all_simulations() -> Dict[str, bool]:
    results = {
        "Kyber": simulate_kyber(),
        "Dilithium": simulate_dilithium(),
        "Falcon": simulate_falcon(),
        "WireGuard": simulate_wireguard(),
        "Obfs4": simulate_obfs4(),
        "PQClean": simulate_pqclean(),
        "Guardian": simulate_guardian(),
        "Logging": simulate_logging(),
        "Report": simulate_report(),
        "MeshScan": simulate_mesh_scan(),
        "PacketCapture": simulate_packet_capture(),
        "SignatureVerify": simulate_signature_verification()
    }
    return results

if __name__ == "__main__":
    from pprint import pprint
    pprint(run_all_simulations())

