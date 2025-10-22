# pqbit/pqbit/report.py

import os
import json
import logging

logger = logging.getLogger("pqbit.report")

def export_signed_report_json(message: str, signature: bytes, public_key: bytes, filename: str = "bit512_report.json"):
    """
    Exports the signed audit report to a JSON file.

    Args:
        message (str): Original audit message
        signature (bytes): Falcon1024 signature
        public_key (bytes): Falcon1024 public key
        filename (str): Output file name or path
    """
    # If filename contains a path separator, use it as-is, otherwise create reports directory
    if "/" in filename or "\\" in filename:
        path = filename
        os.makedirs(os.path.dirname(path), exist_ok=True)
    else:
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

def export_signed_report(message: str, signature: bytes, public_key: bytes, filename: str = "bit512_report.txt"):
    """
    Exports the signed audit report to a plain text file.

    Args:
        message (str): Original audit message
        signature (bytes): Falcon1024 signature
        public_key (bytes): Falcon1024 public key
        filename (str): Output file name
    """
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", filename)

    try:
        with open(path, "w") as f:
            f.write("Bit512 Audit Report\n")
            f.write("===================\n\n")
            f.write(f"Message:\n{message}\n\n")
            f.write(f"Signature:\n{signature.hex()}\n\n")
            f.write(f"Public Key:\n{public_key.hex()}\n")
        logger.info(f"Text report exported to {path}")
    except Exception as e:
        logger.error(f"Failed to export text report: {e}")
