# pqbit/pqbit/kyber.py

import logging
from pqc.kem.kyber1024 import keypair, encap, decap

logger = logging.getLogger("pqbit.kyber")

"""
Kyber Module — Post-quantum cryptography based on key encapsulation.
Using Kyber1024 for maximum security level.
Compatible with PQClean via pypqc.
"""

def kyber_keypair():
    """
    Generates a public and private key pair using Kyber1024.

    Returns:
        tuple: (public_key, secret_key) as bytes
    """
    pk, sk = keypair()
    logger.info("Kyber1024 keypair generated.")
    return pk, sk

def kyber_encapsulate(pk):
    """
    Encapsulates a shared secret using the public key.

    Args:
        pk (bytes): public key

    Returns:
        tuple: (ciphertext, shared_secret) as bytes
    """
    ss, ct = encap(pk)  # pypqc returns (shared_secret, ciphertext)
    logger.info("Shared secret encapsulated using Kyber1024.")
    return ct, ss  # We return (ciphertext, shared_secret) for consistency

def kyber_decapsulate(ct, sk):
    """
    Decapsulates the shared secret using the secret key.

    Args:
        ct (bytes): ciphertext
        sk (bytes): secret key

    Returns:
        bytes: shared secret
    """
    ss = decap(ct, sk)
    logger.info("Shared secret decapsulated using Kyber1024.")
    return ss

