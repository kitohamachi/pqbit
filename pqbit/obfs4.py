# pqbit/pqbit/obfs4.py

import subprocess
import os
import shutil
import logging

logger = logging.getLogger("pqbit.obfs4")

def start_obfs4_proxy(port=1050, cert=None, iat_mode="0"):
    """
    Starts a local Obfs4 proxy using the obfs4proxy binary.

    Requires obfs4proxy to be installed and available in the PATH.

    Args:
        port (int): Port where the proxy will be started
        cert (str): Optional certificate for authentication
        iat_mode (str): Stealth mode (0 = default, 1 = interactive)

    Returns:
        subprocess.Popen or None: Process started or None on error
    """
    obfs4_bin = shutil.which("obfs4proxy")
    if not obfs4_bin:
        logger.error("obfs4proxy not found in PATH.")
        return None

    env = os.environ.copy()
    env["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
    env["TOR_PT_SERVER_BINDADDR"] = f"obfs4-127.0.0.1:{port}"
    env["TOR_PT_ORPORT"] = "127.0.0.1:9001"
    env["TOR_PT_AUTH_COOKIE_FILE"] = "/tmp/obfs4_auth_cookie"
    env["TOR_PT_CERT"] = cert if cert else ""
    env["TOR_PT_EXTENDED_SERVER_PORT"] = str(port)
    env["TOR_PT_IAT_MODE"] = iat_mode

    try:
        process = subprocess.Popen([obfs4_bin], env=env)
        logger.info(f"Obfs4 proxy started on port {port}")
        return process
    except Exception as e:
        logger.error(f"Error starting obfs4proxy: {e}")
        return None
