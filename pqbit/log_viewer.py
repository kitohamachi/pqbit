# pqbit/pqbit/log_viewer.py

import os
import time
import platform
import logging
import yaml
from pqbit import wireshark, benchmark, guardian

LOG_PATH = "logs/benchmark.log"
MESH_PATH = os.path.join(os.path.dirname(__file__), "mesh.yaml")

# 🔧 Logger configuration
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("pqbit.log_viewer")

# -------------------------------
# 📡 Painel Mesh Interativo
# -------------------------------

def show_dashboard(peers):
    print("=== Bit512 Mesh Dashboard ===")
    ranked = guardian.select_best_peer(peers)
    for name, score in ranked:
        peer = next(p for p in peers if p["name"] == name)
        print(f"Peer: {peer['name']}")
        print(f"  Endpoint: {peer['endpoint']}")
        print(f"  Entropia: {peer.get('entropy', 0.0):.2f}")
        print(f"  Latência: {peer.get('latency', 0.0):.2f}s")
        print(f"  Autenticado: {'✔️' if peer.get('auth', False) else '❌'}")
        print(f"  Score: {score:.2f}")
        print()

# -------------------------------
# 📜 Visualização de Logs
# -------------------------------

def tail_log(lines=20):
    if not os.path.exists(LOG_PATH):
        print("No logs found.")
        return

    with open(LOG_PATH, "r") as f:
        content = f.readlines()[-lines:]

    for line in content:
        if "INFO" in line:
            print(f"\033[94m{line.strip()}\033[0m")  # blue
        elif "WARNING" in line:
            print(f"\033[93m{line.strip()}\033[0m")  # yellow
        elif "ERROR" in line:
            print(f"\033[91m{line.strip()}\033[0m")  # red
        else:
            print(line.strip())

# -------------------------------
# 🧹 Limpeza de Tela
# -------------------------------

def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

# -------------------------------
# 🛡️ Auditoria Guardian
# -------------------------------

def run_guardian():
    print("\n🧠 Running a full audit with Bit512 Guardian...\n")
    guardian.run_guardian_audit(interface="tun0", duration=30)
    input("\n🛡️ Press Enter to return to viewing logs...")

# -------------------------------
# 🚀 Benchmark de Túnel
# -------------------------------

def run_benchmark():
    print("\n🚀 Running tunnel benchmark...\n")
    result = benchmark.benchmark_tunnel(verbose=True)
    if result["status"] == "ok":
        logger.info(f"Benchmark completed: Latency = {result['latency']:.2f}s, Camouflage = {result['camouflage']}")
    elif result["status"] == "timeout":
        logger.warning("Benchmark failed: timeout exceeded.")
    else:
        logger.error("Benchmark failed: unexpected error.")
    input("\n📊 Press Enter to return to viewing logs...")

# -------------------------------
# 📁 Carregamento de mesh.yaml
# -------------------------------

def load_mesh_yaml(path=MESH_PATH):
    if not os.path.exists(path):
        logger.error(f"Mesh config file '{path}' not found.")
        return []
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("peers", [])
    except Exception as e:
        logger.error(f"Failed to load mesh.yaml: {e}")
        return []

def get_real_peers():
    peers = load_mesh_yaml()
    for peer in peers:
        ip = peer["endpoint"].split(":")[0]
        peer["latency"] = guardian.measure_latency(ip)
        peer["entropy"] = guardian.calculate_entropy(peer.get("recent_data", b""))
    return peers

# -------------------------------
# 🎛️ Interface Principal
# -------------------------------

if __name__ == "__main__":
    try:
        while True:
            clear_screen()
            print("📡 Real-time logs (Ctrl+C to exit):\n")
            tail_log()

            print("\n[1] Run a full audit (Bit512 Guardian)")
            print("[2] Run a tunnel benchmark")
            print("[3] Show mesh dashboard")
            print("[4] Continue monitoring logs")

            choice = input("\nChoose an option: ").strip()
            if choice == "1":
                run_guardian()
            elif choice == "2":
                run_benchmark()
            elif choice == "3":
                clear_screen()
                peers = get_real_peers()
                show_dashboard(peers)
                input("\n🔁 Press Enter to return to menu...")
            elif choice == "4":
                time.sleep(2)
            else:
                print("❌ Invalid option.")
                time.sleep(2)

    except KeyboardInterrupt:
        logger.warning("Monitoring terminated by user.")
        print("\n🛑 Monitoring terminated by user.")
