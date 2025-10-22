# pqbit/pqbit/wireguard.py

import subprocess
import os
import logging

logger = logging.getLogger("pqbit.wireguard")

def setup_wireguard_tunnel(config_path="/etc/wireguard/wg0.conf"):
    """
    Activates a WireGuard tunnel using a configuration file.

    Requires the 'wg-quick' command to be available on the system.

    Args:
        config_path (str): Path to the WireGuard configuration file

    Returns:
        bool: True if the tunnel was activated successfully, False otherwise
    """
    if not os.path.isfile(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        return False

    try:
        subprocess.run(["sudo", "wg-quick", "up", config_path], check=True)
        logger.info(f"WireGuard tunnel activated with {config_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error activating WireGuard tunnel: {e}")
        return False

def teardown_wireguard_tunnel(config_path="/etc/wireguard/wg0.conf"):
    """
    Disables the WireGuard tunnel using the same configuration file.

    Args:
        config_path (str): Path to the WireGuard configuration file

    Returns:
        bool: True if the tunnel is successfully disabled, False otherwise
    """
    if not os.path.isfile(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        return False

    try:
        subprocess.run(["sudo", "wg-quick", "down", config_path], check=True)
        logger.info(f"WireGuard tunnel disabled with {config_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error disabling WireGuard tunnel: {e}")
        return False
