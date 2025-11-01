# /pqbit/pqbit/benchmark.py

import os
import time
import platform
import logging
import socket
from typing import Dict, Any
from pqbit import wireshark

LOG_PATH = "logs/benchmark.log"

__all__ = ["benchmark_tunnel", "tail_log", "clear_screen", "run_guardian", "run_benchmark"]

# 🔧 Logger configuration
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def benchmark_tunnel(verbose: bool = False, timeout: int = 10) -> Dict[str, Any]:
    """
    Benchmarks the tunnel by measuring latency and checking for traffic obfuscation.

    Args:
        verbose (bool): If True, prints detailed information during the benchmark.
        timeout (int): Maximum time in seconds to wait for the benchmark to complete.

    Returns:
        dict: A dictionary with keys:
            - status (str): "ok", "timeout", or "error"
            - latency (float): Measured latency in seconds (or None if failed)
            - camouflage (bool): True if traffic appears obfuscated
    """
    if verbose:
        print("Starting tunnel benchmark...")
    
    start_time = time.time()
    
    try:
        # Measure latency by attempting to connect to a test endpoint
        test_host = "8.8.8.8"
        test_port = 53
        
        try:
            sock = socket.create_connection((test_host, test_port), timeout=timeout)
            sock.close()
            latency = time.time() - start_time
            
            if verbose:
                print(f"Latency measured: {latency:.2f}s")
            
            # Check for traffic obfuscation (simplified check)
            # In a real scenario, this would analyze packet entropy
            camouflage = latency < 5.0  # Simplified heuristic
            
            if verbose:
                print(f"Camouflage status: {'✅' if camouflage else '❌'}")
            
            return {
                "status": "ok",
                "latency": latency,
                "camouflage": camouflage
            }
        except socket.timeout:
            if verbose:
                print("Benchmark timed out")
            return {
                "status": "timeout",
                "latency": None,
                "camouflage": False
            }
    except Exception as e:
        if verbose:
            print(f"Benchmark error: {e}")
        logging.error(f"Benchmark error: {e}")
        return {
            "status": "error",
            "latency": None,
            "camouflage": False
        }

def tail_log(lines: int = 20) -> None:
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

def clear_screen() -> None:
    """
    Clears the screen in a manner compatible with the operating system.
    """
    os.system("cls" if platform.system() == "Windows" else "clear")

def run_guardian() -> None:
    """
    Runs the Bit512 Guardian audit on the default interface.
    """
    logging.info("Starting traffic audit with Bit512 Guardian.")
    print("\n🧠 Running traffic audit with Bit512 Guardian...\n")
    wireshark.audit(interface="tun0", duration=30)
    logging.info("Traffic audit completed.")
    input("\n🛡️ Press Enter to return to log view...")

def run_benchmark() -> None:
    """
    Runs the tunnel benchmark test.
    """
    logging.info("Starting tunnel benchmark.")
    print("\n🚀 Running tunnel benchmark...\n")
    result = benchmark_tunnel(verbose=True)

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

