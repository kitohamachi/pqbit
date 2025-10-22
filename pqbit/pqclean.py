# pqbit/pqbit/pqclean.py

import os
import subprocess
import logging

logger = logging.getLogger("pqbit.pqclean")

PQ_CLEAN_PATH = os.path.expanduser("~/PQClean")  # Adjust according to your local structure

def list_supported_algorithms():
    """
    Lists the algorithms available in the PQClean repository.

    Returns:
        list: List of strings in the format "KEM: kyber1024" or "SIGN: dilithium5"
    """
    algorithms = []
    kem_path = os.path.join(PQ_CLEAN_PATH, "crypto_kem")
    sign_path = os.path.join(PQ_CLEAN_PATH, "crypto_sign")

    for category, path in [("KEM", kem_path), ("SIGN", sign_path)]:
        if os.path.isdir(path):
            for algo in os.listdir(path):
                if os.path.isdir(os.path.join(path, algo)):
                    algorithms.append(f"{category}: {algo}")

    logger.info(f"{len(algorithms)} algorithms found in PQClean.")
    return algorithms

def compile_pqclean(algorithm, category="kem"):
    """
    Compiles a specific PQClean algorithm using make.

    Args:
        algorithm (str): Algorithm name (e.g., kyber1024)
        category (str): Algorithm type: "kem" or "sign"

    Returns:
        bool: True if compiled successfully, False otherwise
    """
    if category not in ["kem", "sign"]:
        logger.error(f"Invalid category: {category}")
        return False

    algo_path = os.path.join(PQ_CLEAN_PATH, f"crypto_{category}", algorithm)
    if not os.path.isdir(algo_path):
        logger.error(f"Algorithm not found: {algorithm}")
        return False

    try:
        subprocess.run(["make"], cwd=algo_path, check=True)
        logger.info(f"{algorithm} compiled successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error compiling {algorithm}: {e}")
        return False
