# pqbit/pqbit/benchmark_routes.py

import time
import logging
from pqbit.benchmark import benchmark_tunnel
from pqbit.wireguard import setup_wireguard_tunnel
from pqbit.obfs4 import start_obfs4_proxy

logger = logging.getLogger("pqbit.benchmark")

def benchmark_direct():
    logger.info("🔓 Starting benchmark via direct connection")
    return benchmark_tunnel(verbose=True)

def benchmark_wireguard():
    logger.info("🛡️ Starting benchmark via WireGuard")
    if setup_wireguard_tunnel():
        result = benchmark_tunnel(verbose=True)
        logger.info(f"WireGuard: Latency {result['latency']}, Camouflage {result['camouflage']}")
        return result
    logger.error("WireGuard failed to start")
    return {"latency": None, "camouflage": False, "status": "wireguard_failed"}

def benchmark_obfs4():
    logger.info("🕵️‍♂️ Starting benchmark via Obfs4")
    proc = start_obfs4_proxy(port=1050)
    if proc:
        time.sleep(2)  # time to stabilize proxy
        result = benchmark_tunnel(verbose=True)
        logger.info(f"Obfs4: Latency {result['latency']}, Camouflage {result['camouflage']}")
        return result
    logger.error("Obfs4 failed to start")
    return {"latency": None, "camouflage": False, "status": "obfs4_failed"}

def benchmark_combined():
    logger.info("🧱 Starting benchmark via WireGuard + Obfs4")
    wg_ok = setup_wireguard_tunnel()
    proc = start_obfs4_proxy(port=1050)
    if wg_ok and proc:
        time.sleep(2)
        result = benchmark_tunnel(verbose=True)
        logger.info(f"Combined: Latency {result['latency']}, Camouflage {result['camouflage']}")
        return result
    logger.error("Failed to start combined tunnel")
    return {"latency": None, "camouflage": False, "status": "combined_failed"}

def run_all_benchmarks():
    results = {
        "direct": benchmark_direct(),
        "wireguard": benchmark_wireguard(),
        "obfs4": benchmark_obfs4(),
        "combined": benchmark_combined()
    }

    print("\n📊 Comparative Results:")
    for route, result in results.items():
        latency = result["latency"]
        camo = "✅" if result["camouflage"] else "❌"
        status = result["status"]
        latency_str = f"{latency:.2f}s" if latency else "N/A"
        print(f"- {route:<10} | Latency: {latency_str} | Camouflage: {camo} | Status: {status}")

    return results

if __name__ == "__main__":
    run_all_benchmarks()
