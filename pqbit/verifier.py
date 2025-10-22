# pqbit/pqbit/verifier.py

import os
import json
import logging
from . import falcon

logger = logging.getLogger("pqbit.verifier")

def verify_report(message: str, hex_signature: str, hex_public_key: str) -> bool:
    """
    Verifies the authenticity of a signed audit report.

    Args:
        message (str): Original message
        hex_signature (str): Signature in hex format
        hex_public_key (str): Public key in hex format

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        signature = bytes.fromhex(hex_signature)
        public_key = bytes.fromhex(hex_public_key)
        result = falcon.falcon_verify(message.encode(), signature, public_key)
        logger.info("Verification completed: %s", "valid" if result else "invalid")
        return result
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False

def export_signed_report_json(message: str, signature: bytes, public_key: bytes, filename: str = "bit512_report.json"):
    """
    Exports the signed audit report to a JSON file.

    Args:
        message (str): Original audit message
        signature (bytes): Falcon1024 signature
        public_key (bytes): Falcon1024 public key
        filename (str): Output file name
    """
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", filename)

    report = {
        "message": message,
        "signature": signature.hex(),
        "public_key": public_key.hex()
    }

    try:
        with open(path, "w") as f:
            json.dump(report, f, indent=4)
        logger.info(f"JSON report exported to {path}")
    except Exception as e:
        logger.error(f"Failed to export JSON report: {e}")
