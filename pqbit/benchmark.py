# /pqbit/pqbit/benchmark.py

import os
import time
import platform
import logging
from pqbit import wireshark, benchmark as bmark  # avoid name conflict with this file

LOG_PATH = "logs/benchmark.log"

# 🔧 Logger configuration
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def tail_log(lines=20):
    """
    Displays the last lines of the log, colored by severity level.
    """
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

def clear_screen():
    """
    Clears the screen in a manner compatible with the operating system.
    """
    os.system("cls" if platform.system() == "Windows" else "clear")

def run_guardian():
    """
    Runs the Bit512 Guardian audit on the default interface.
    """
    logging.info("Starting traffic audit with Bit512 Guardian.")
    print("\n🧠 Running traffic audit with Bit512 Guardian...\n")
    wireshark.audit(interface="tun0", duration=30)
    logging.info("Traffic audit completed.")
    input("\n🛡️ Press Enter to return to log view...")

def run_benchmark():
    """
    Runs the tunnel benchmark test.
    """
    logging.info("Starting tunnel benchmark.")
    print("\n🚀 Running tunnel benchmark...\n")
    result = bmark.benchmark_tunnel(verbose=True)

    if result["status"] == "ok":
        logging.info(f"Benchmark completed: Latency = {result['latency']:.2f}s, Cloaking = {result['camouflage']}")
    elif result["status"] == "timeout":
        logging.warning("Benchmark failed: timeout exceeded.")
    else:
        logging.error("Benchmark failed: unexpected error.")

    input("\n📊 Press Enter to return to the log view...")

if __name__ == "__main__":
    try:
        while True:
            clear_screen()
            print("📡 Real-time logs (Ctrl+C to exit):\n")
            tail_log()

            print("\n[1] Run traffic audit (Bit512 Guardian)")
            print("[2] Run tunnel benchmark")
            print("[3] Continue monitoring logs")
            print("[Ctrl+C] Exit")

            choice = input("\nChoose an option: ").strip()
            if choice == "1":
                run_guardian()
            elif choice == "2":
                run_benchmark()
            elif choice == "3":
                time.sleep(2)
            else:
                print("❌ Invalid option.")
                time.sleep(2)

    except KeyboardInterrupt:
        logging.warning("Monitoring terminated by user.")
        print("\n🛑 Monitoring terminated by user.")

