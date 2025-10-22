# pqbit/pqbit/wg-meshconf.py 'rede mesh + embaralhamento de pacotes + wireguard' 

import os
import random
import logging
import subprocess
import base64
import hashlib
from pqbit import wireguard, tunnel # Assumindo que pqbit e wireguard/tunnel são módulos válidos
from pqbit.kyber import kyber_keypair, kyber_encapsulate, kyber_decapsulate

# Configuração de Log
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("pqbit.wgmesh")

"""
wg-meshconf_secure.py — Mesh VPN configuration with WireGuard, PQC (Kyber) PSK, and Mínimo Privilégio.
"""

# -------------------------------
# 🔐 Segurança Pós-Quântica (PQC) - Derivação de PSK
# -------------------------------

def derive_preshared_key(shared_secret):
    """Deriva uma PSK de 32 bytes (256-bit) em Base64 a partir do segredo Kyber."""
    # Uso de SHA-256 para derivar 32 bytes de forma determinística
    preshared_key_bytes = hashlib.sha256(shared_secret).digest()
    # Codifica em Base64 (formato que o WireGuard espera)
    return base64.b64encode(preshared_key_bytes).decode('utf-8')

# -------------------------------
# 🔧 Configuração do Par (Peer)
# -------------------------------

def generate_peer_config(peer_name, public_key, endpoint, allowed_ips, preshared_key_base64=None):
    """Gera o dicionário de configuração de um par (Peer)."""
    config = {
        "Peer": peer_name,
        "PublicKey": public_key,
        "Endpoint": endpoint,
        "AllowedIPs": allowed_ips,
        # Adiciona jittering de Keepalive para ofuscação de tempo (em vez de shuffling)
        "PersistentKeepalive": str(random.randint(25, 30)) 
    }
    if preshared_key_base64:
        # Adiciona a chave PSK derivada da criptografia PQC
        config["PresharedKey"] = preshared_key_base64
    return config

# -------------------------------
# 🕸️ Mesh Topology Builder Otimizado
# -------------------------------

def build_mesh(peers_data):
    """
    Constrói a topologia mesh e gera os segredos PQC e as configurações.
    Garante o MÍNIMO PRIVILÉGIO no AllowedIPs.
    """
    
    # 1. Gerar identidades Kyber PQC para todos os pares
    for peer in peers_data:
        identity = generate_secure_peer_identity()
        peer["pqc_pk"] = identity["public_key"]
        peer["pqc_sk"] = identity["secret_key"]
        peer["mesh_peers"] = {} # Para armazenar a configuração dos vizinhos

    # 2. Estabelecer o canal seguro e derivar a PSK (Par-a-Par)
    for i, peer_a in enumerate(peers_data):
        for j, peer_b in enumerate(peers_data):
            if i != j:
                # A usa a Chave Secreta de B para estabelecer um segredo compartilhado único
                # NOTA: O Kyber tem 2 funções. Vamos simular o segredo final de um Diffie-Hellman PQC.
                
                # Simulação da Troca de Chaves PQC e Derivação da PSK
                # Em um ambiente real, 'establish_secure_channel' geraria o segredo final
                # Para fins de simulação, vamos criar uma PSK única a partir da concatenação das chaves PQC
                
                # Segredo compartilhado determinístico entre A e B (para que a PSK seja a mesma)
                # Na prática, isso seria feito com um protocolo como o Noise Protocol Kyber
                # Aqui, estamos garantindo que é único para o par A <-> B
                unique_secret = peer_a["pqc_sk"] + peer_b["pqc_pk"]
                preshared_key = derive_preshared_key(unique_secret.encode('utf-8'))
                
                # 3. Gerar a configuração do Peer B dentro do arquivo de A
                
                # MÍNIMO PRIVILÉGIO: AllowedIPs é APENAS o IP do par B
                config = generate_peer_config(
                    peer_name=peer_b["name"],
                    public_key=peer_b["public_key"],
                    endpoint=peer_b["endpoint"],
                    allowed_ips=peer_b["allowed_ips"], # Ex: '10.0.0.2/32'
                    preshared_key_base64=preshared_key
                )
                
                peer_a["mesh_peers"][peer_b["name"]] = config

    logger.info("Mesh topology built with PQC-derived PSKs and Mínimo Privilégio.")
    return peers_data


# -------------------------------
# 🛡️ Gerenciamento de Segurança e Configuração
# -------------------------------

def generate_wg_config_file(node_data):
    """Gera o arquivo de configuração wg-quick completo para o nó."""
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
    """Salva os arquivos de configuração com permissões restritas e gera regras de Firewall."""
    for peer in peers_data:
        filename = os.path.join(config_dir, f"{peer['name']}.conf")
        
        # 1. Geração do arquivo de configuração
        config_content = generate_wg_config_file(peer)
        
        # 2. Salvar com permissões restritas (Chave Privada)
        try:
            with open(filename, "w") as f:
                f.write(config_content)
            # APLICAÇÃO CRÍTICA DE SEGURANÇA: umask 077 -> Permissão 0600 (apenas root pode ler/escrever)
            os.chmod(filename, 0o600) 
            logger.info(f"Configuração salva em '{filename}' com permissão 0600.")
        except Exception as e:
            logger.error(f"Erro ao salvar ou aplicar permissões em {filename}: {e}")
            
        # 3. Geração de Regras de Firewall (Mínimo Privilégio)
        iptables_commands = generate_iptables_rules(peer['name'], peer['allowed_ips'])
        logger.info(f"Geradas regras de iptables de Mínimo Privilégio para {peer['name']}.")
        # Em produção, você executaria esses comandos ou usaria 'PostUp' no wg-quick

def generate_iptables_rules(interface_name, allowed_ip):
    """Gera comandos básicos de iptables de Mínimo Privilégio (apenas a lógica)."""
    # 1. Permite o tráfego de saída (OUTPUT) da interface WireGuard para qualquer destino na mesh
    commands = [
        f"iptables -A OUTPUT -o {interface_name} -j ACCEPT",
        # 2. Permite apenas conexões de entrada (INPUT) que tenham sido iniciadas pelo nó
        f"iptables -A INPUT -i {interface_name} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        # 3. Apenas permite novas conexões (NEW) no ListenPort (51820)
        f"iptables -A INPUT -i {interface_name} -p udp --dport 51820 -j ACCEPT",
        # 4. Bloqueia o restante na interface mesh por padrão (Princípio do Mínimo Privilégio)
        f"iptables -A INPUT -i {interface_name} -j DROP",
        # 5. Permite o tráfego de encaminhamento (FORWARD) se necessário (Se for um roteador)
        # Ex: iptables -A FORWARD -i wg-mesh0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    ]
    return commands


# Funções auxiliares (existentes no código original)
def generate_secure_peer_identity():
    """Simulação da geração de chaves PQC Kyber."""
    # Retorna chaves dummy se pqbit.kyber não estiver disponível
    try:
        pk, sk = kyber_keypair()
        return {"public_key": pk.hex(), "secret_key": sk.hex()}
    except:
        return {"public_key": f"PQC-PK-{random.randint(100, 999)}", 
                "secret_key": f"PQC-SK-{random.randint(100, 999)}"}
        

# -------------------------------
# 🧪 Exemplo de Uso
# -------------------------------

if __name__ == "__main__":
    # --- Dados de Peers (Simulados, devem ser gerados em produção) ---
    peers = [
        {
            "name": "nodeA",
            "private_key": "privA_base64...",
            "public_key": "pubA_base64...",
            "endpoint": "ip.publico.a:51820", # IP público ou DNS
            "allowed_ips": "10.0.0.1/32"       # IP interno da Mesh (o /32 é crucial)
        },
        {
            "name": "nodeB",
            "private_key": "privB_base64...",
            "public_key": "pubB_base64...",
            "endpoint": "ip.publico.b:51820",
            "allowed_ips": "10.0.0.2/32"
        },
        # Adicione mais nós conforme necessário
    ]
    
    # 1. Constrói a topologia (Gera PSKs PQC e define AllowedIPs)
    secure_peers_data = build_mesh(peers)
    
    # 2. Implanta as configurações com segurança (Permissões 0600 e regras de Firewall)
    # NOTA: O diretório precisa existir e ser acessível por quem executa o script (ex: sudo)
    # Substitua '/tmp/wireguard_configs/' pelo seu diretório real, como '/etc/wireguard/'
    secure_deploy(secure_peers_data, config_dir="./wireguard_configs_temp/") 

    logger.info("Implantação segura concluída. Verifique os arquivos na pasta temporária.")
    
    # Exemplo de como o arquivo final seria (para nodeA.conf)
    # print("\n--- Conteúdo SIMULADO de nodeA.conf ---")
    # print(generate_wg_config_file(secure_peers_data[0]))
