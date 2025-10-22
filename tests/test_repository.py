# tests/test_repository.py

import logging
import os
import json
import pytest

from pqbit import kyber_keypair, kyber_encapsulate, kyber_decapsulate

from pqbit import falcon
from pqbit import report
from pqbit import verifier
from pqbit.simulation import run_all_simulations

logger = logging.getLogger("pqbit.tests")

# -------------------------------
# 🔁 Integration Simulation Test
# -------------------------------

def test_run_all_simulations():
    results = run_all_simulations()
    assert isinstance(results, dict)
    assert all(key in results for key in [
        "Kyber", "Dilithium", "Falcon", "WireGuard", "Obfs4",
        "PQClean", "Guardian", "Logging", "Report",
        "MeshScan", "PacketCapture", "SignatureVerify"
    ])
    logger.info("Simulation integration test executed successfully.")
    for module, result in results.items():
        logger.info(f"{module} simulation result: {result}")

# -------------------------------
# 🔐 Kyber1024 Tests
# -------------------------------

def test_kyber_keypair_generation():
    pk, sk = kyber_keypair()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) > 0
    assert len(sk) > 0
    logger.info("Kyber1024 keypair generated successfully.")

def test_kyber_encapsulation_cycle():
    pk, sk = kyber_keypair()
    ct, ss1 = kyber_encapsulate(pk)
    ss2 = kyber_decapsulate(ct, sk)
    assert ss1 == ss2
    logger.info("Kyber1024 encapsulation/decapsulation cycle verified.")

def test_kyber_invalid_decapsulation():
    pk, sk = kyber_keypair()
    ct, ss1 = kyber_encapsulate(pk)
    _, sk2 = kyber_keypair()
    ss2 = kyber_decapsulate(ct, sk2)
    assert ss1 != ss2
    logger.info("Kyber1024 decapsulation with wrong key failed as expected.")

# -------------------------------
# ✍️ Falcon Tests
# -------------------------------

def test_falcon_keypair_generation():
    pk, sk = falcon.falcon_keypair()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    logger.info("Falcon keypair generated successfully.")

def test_falcon_signature_and_verification():
    msg = b"Bit512 test message"
    pk, sk = falcon.falcon_keypair()
    sig = falcon.falcon_sign(msg, sk)
    assert falcon.falcon_verify(msg, sig, pk)
    logger.info("Falcon signature verified successfully.")

# -------------------------------
# 📄 Report Tests
# -------------------------------

def test_export_signed_report_json(tmp_path):
    msg = "Audit test"
    sig = b"\x01\x02\x03"
    pk = b"\x04\x05\x06"
    filename = "test_report.json"
    path = tmp_path / filename

    report.export_signed_report_json(msg, sig, pk, filename=str(path))

    with open(path, "r") as f:
        data = json.load(f)

    assert data["message"] == msg
    assert data["signature"] == sig.hex()
    assert data["public_key"] == pk.hex()
    logger.info("Report JSON exported and validated.")

# -------------------------------
# ✅ Verifier Tests
# -------------------------------

def test_verification_success():
    msg = "Bit512 verification test"
    pk, sk = falcon.falcon_keypair()
    sig = falcon.falcon_sign(msg.encode(), sk)

    result = verifier.verify_report(msg, sig.hex(), pk.hex())
    assert result is True
    logger.info("Verifier confirmed valid signature.")

def test_verification_failure():
    msg = "Bit512 altered message"
    pk, sk = falcon.falcon_keypair()
    sig = falcon.falcon_sign(b"original message", sk)

    result = verifier.verify_report(msg, sig.hex(), pk.hex())
    assert result is False
    logger.info("Verifier rejected altered message as expected.")

