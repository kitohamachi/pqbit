# pqbit/pqbit/log_benchmark.py

import os
import json
import logging
from datetime import datetime
from pqbit.benchmark_routes import run_all_benchmarks

# Logger configuration
logger = logging.getLogger("pqbit.benchmark")
logger.setLevel(logging.INFO)

# Log format
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

# Console output
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Output to file
os.makedirs("logs", exist_ok=True)
log_file = os.path.join("logs", "benchmark.log")
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def save_benchmark_json(results, output_dir="logs"):
    """
    Save the benchmark results to a JSON file with a timestamp.

    Args:
        results (dict): Results returned by run_all_benchmarks()
        output_dir (str): Folder where the file will be saved
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"benchmark_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = {
        "timestamp": datetime.now().isoformat(),
        "version": "0.1.0",
        "system": "Bit512 Tunnel",
        "results": results
    }

    try:
        with open(filepath, "w") as f:
            json.dump(metadata, f, indent=4)
        logger.info(f"Benchmark saved in {filepath}")
    except Exception as e:
        logger.error(f"Error saving benchmark: {e}")

def run_and_log_benchmarks():
    """
    Runs all benchmarks and saves the results in JSON.
    """
    logger.info("Starting benchmark execution...")
    results = run_all_benchmarks()
    save_benchmark_json(results)
    logger.info("Benchmarks completed and logged.")

if __name__ == "__main__":
    run_and_log_benchmarks()
