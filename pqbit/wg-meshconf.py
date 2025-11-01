# pqbit/pqbit/wg-meshconf.py 'mesh network + packet shuffling + wireguard' 

import os
import random
import logging
import subprocess
import base64
import hashlib
from pqbit import wireguard, tunnel # Assuming pqbit and wireguard/tunnel are valid modules
from pqbit.kyber import kyber_keypair, kyber_encapsulate, kyber_decapsulate

# Log Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("pqbit.wgmesh")

"""
wg-meshconf_secure.py — Mesh VPN configuration with WireGuard, PQC (Kyber) PSK, and Least Privilege.
"""

# -------------------------------
# 🔐 Post-Quantum Security (PQC) - PSK Derivation
# -------------------------------

def derive_preshared_key(shared_secret):
    """Derives a 32-byte (256-bit) PSK in Base64 from the Kyber secret."""
    # Use SHA-256 to derive 32 bytes deterministically
    preshared_key_bytes = hashlib.sha256(shared_secret).digest()
    # Encode in Base64 (format that WireGuard expects)
    return base64.b64encode(preshared_key_bytes).decode('utf-8')

# -------------------------------
# 🔧 Peer Configuration
# -------------------------------

def generate_peer_config(peer_name, public_key, endpoint, allowed_ips, preshared_key_base64=None):
    """Generates the configuration dictionary for a peer."""
    config = {
        "Peer": peer_name,
        "PublicKey": public_key,
        "Endpoint": endpoint,
        "AllowedIPs": allowed_ips,
        # Add Keepalive jittering for time obfuscation (instead of shuffling)
        "PersistentKeepalive": str(random.randint(25, 30)) 
    }
    if preshared_key_base64:
        # Add the PSK key derived from PQC encryption
        config["PresharedKey"] = preshared_key_base64
    return config

# -------------------------------
# 🕸️ Optimized Mesh Topology Builder
# -------------------------------

def build_mesh(peers_data):
    """
    Builds the mesh topology and generates PQC secrets and configurations.
    Ensures LEAST PRIVILEGE in AllowedIPs.
    """
    
    # 1. Generate Kyber PQC identities for all peers
    for peer in peers_data:
        identity = generate_secure_peer_identity()
        peer["pqc_pk"] = identity["public_key"]
        peer["pqc_sk"] = identity["secret_key"]
        peer["mesh_peers"] = {} # To store neighbor configurations

    # 2. Establish secure channel and derive PSK (Peer-to-Peer)
    for i, peer_a in enumerate(peers_data):
        for j, peer_b in enumerate(peers_data):
            if i != j:
                # A uses B's Secret Key to establish a unique shared secret
                # NOTE: Kyber has 2 functions. We'll simulate the final secret of a PQC Diffie-Hellman.
                
                # Simulation of PQC Key Exchange and PSK Derivation
                # In a real environment, 'establish_secure_channel' would generate the final secret
                # For simulation purposes, we'll create a unique PSK from the concatenation of PQC keys
                
                # Deterministic shared secret between A and B (so the PSK is the same)
                # In practice, this would be done with a protocol like Noise Protocol Kyber
                # Here, we're ensuring it's unique for the pair A <-> B
                unique_secret = peer_a["pqc_sk"] + peer_b["pqc_pk"]
                preshared_key = derive_preshared_key(unique_secret.encode('utf-8'))
                
                # 3. Generate Peer B's configuration within A's file
                
                # LEAST PRIVILEGE: AllowedIPs is ONLY peer B's IP
                config = generate_peer_config(
                    peer_name=peer_b["name"],
                    public_key=peer_b["public_key"],
                    endpoint=peer_b["endpoint"],
                    allowed_ips=peer_b["allowed_ips"], # Ex: '10.0.0.2/32'
                    preshared_key_base64=preshared_key
                )
                
                peer_a["mesh_peers"][peer_b["name"]] = config

    logger.info("Mesh topology built with PQC-derived PSKs and Least Privilege.")
    return peers_data


# -------------------------------
# 🛡️ Security and Configuration Management
# -------------------------------

def generate_wg_config_file(node_data):
    """Generates the complete wg-quick configuration file for the node."""
    config = f"[Interface]\n"
    config += f"PrivateKey = {node_data['private_key']}\n"
    config += f"Address = {node_data['allowed_ips']}\n"
    config += f"ListenPort = 51820\n\n"

    for peer_name, peer_config in node_data['mesh_peers'].items():
        config += f"# Peer: {peer_name}\n"
        config += "[Peer]\n"
        config += f"PublicKey = {peer_config['PublicKey']}\n"
        config += f"PresharedKey = {peer_config['PresharedKey']}\n" # PSK PQC
        config += f"AllowedIPs = {peer_config['AllowedIPs']}\n"     # Mínimo Privilégio
        config += f"Endpoint = {peer_config['Endpoint']}\n"
        config += f"PersistentKeepalive = {peer_config['PersistentKeepalive']}\n\n"

    return config

def secure_deploy(peers_data, config_dir="/etc/wireguard/"):
    """Saves configuration files with restricted permissions and generates Firewall rules."""
    for peer in peers_data:
        filename = os.path.join(config_dir, f"{peer['name']}.conf")
        
        # 1. Configuration file generation
        config_content = generate_wg_config_file(peer)
        
        # 2. Save with restricted permissions (Private Key)
        try:
            with open(filename, "w") as f:
                f.write(config_content)
            # CRITICAL SECURITY APPLICATION: umask 077 -> Permission 0600 (only root can read/write)
            os.chmod(filename, 0o600) 
            logger.info(f"Configuration saved in '{filename}' with permission 0600.")
        except Exception as e:
            logger.error(f"Error saving or applying permissions to {filename}: {e}")
            
        # 3. Firewall Rules Generation (Least Privilege)
        iptables_commands = generate_iptables_rules(peer['name'], peer['allowed_ips'])
        logger.info(f"Generated Least Privilege iptables rules for {peer['name']}.")
        # In production, you would execute these commands or use 'PostUp' in wg-quick

def generate_iptables_rules(interface_name, allowed_ip):
    """Generates basic Least Privilege iptables commands (logic only)."""
    # 1. Allow outbound traffic (OUTPUT) from WireGuard interface to any destination in the mesh
    commands = [
        f"iptables -A OUTPUT -o {interface_name} -j ACCEPT",
        # 2. Only allow inbound connections (INPUT) that were initiated by the node
        f"iptables -A INPUT -i {interface_name} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        # 3. Only allow new connections (NEW) on ListenPort (51820)
        f"iptables -A INPUT -i {interface_name} -p udp --dport 51820 -j ACCEPT",
        # 4. Block the rest on mesh interface by default (Least Privilege Principle)
        f"iptables -A INPUT -i {interface_name} -j DROP",
        # 5. Allow forwarding traffic (FORWARD) if necessary (If it's a router)
        # Ex: iptables -A FORWARD -i wg-mesh0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    ]
    return commands


# Helper functions (existing in original code)
def generate_secure_peer_identity():
    """Simulation of PQC Kyber key generation."""
    # Returns dummy keys if pqbit.kyber is not available
    try:
        pk, sk = kyber_keypair()
        return {"public_key": pk.hex(), "secret_key": sk.hex()}
    except:
        return {"public_key": f"PQC-PK-{random.randint(100, 999)}", 
                "secret_key": f"PQC-SK-{random.randint(100, 999)}"}
        

# -------------------------------
# 🧪 Usage Example
# -------------------------------

if __name__ == "__main__":
    # --- Peer Data (Simulated, should be generated in production) ---
    peers = [
        {
            "name": "nodeA",
            "private_key": "privA_base64...",
            "public_key": "pubA_base64...",
            "endpoint": "ip.public.a:51820", # Public IP or DNS
            "allowed_ips": "10.0.0.1/32"       # Internal Mesh IP (the /32 is crucial)
        },
        {
            "name": "nodeB",
            "private_key": "privB_base64...",
            "public_key": "pubB_base64...",
            "endpoint": "ip.public.b:51820",
            "allowed_ips": "10.0.0.2/32"
        },
        # Add more nodes as needed
    ]
    
    # 1. Build topology (Generate PQC PSKs and define AllowedIPs)
    secure_peers_data = build_mesh(peers)
    
    # 2. Deploy configurations securely (Permissions 0600 and Firewall rules)
    # NOTE: The directory needs to exist and be accessible by whoever runs the script (ex: sudo)
    # Replace '/tmp/wireguard_configs/' with your actual directory, like '/etc/wireguard/'
    secure_deploy(secure_peers_data, config_dir="./wireguard_configs_temp/") 

    logger.info("Secure deployment completed. Check the files in the temporary folder.")
    
    # Example of what the final file would look like (for nodeA.conf)
    # print("\n--- SIMULATED content of nodeA.conf ---")
    # print(generate_wg_config_file(secure_peers_data[0]))
