# 🧠 pqbit

![PyPI](https://img.shields.io/pypi/v/pqbit)
![License](https://img.shields.io/github/license/kitohamachi/pqbit)
![Build](https://img.shields.io/github/actions/workflow/status/kitohamachi/pqbit/python-app.yml)
![Coverage](https://img.shields.io/codecov/c/github/kitohamachi/pqbit)

---

**Author**: Kito Hamachi — Bit512 Labs  
**License**: MIT  
**Repository**: [github.com/kitohamachi/pqbit](https://github.com/kitohamachi/pqbit)  
**PyPI**: [pypi.org/project/pqbit](https://pypi.org/project/pqbit)

---

## 📖 Table of Contents

- [🧪 Usage Examples](#-usage-examples)
- [🧩 Key Components](#-key-components)
- [📦 Objective](#-objective)
- [🔐 Supported Algorithms and Technologies](#-supported-algorithms-and-technologies)
- [📁 Module Overview](#-module-overview)
- [📦 Installation](#-installation)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [🙏 Gratitude](#-gratitude)

---

## 🧪 Usage Examples

```python
from pqbit import falcon_keypair, falcon_sign, falcon_verify

pk, sk = falcon_keypair()
message = b"Bit512 integrity test"
signature = falcon_sign(message, sk)

if falcon_verify(message, signature, pk):
    print("Signature verified ✅")
else:
    print("Signature failed ❌")
```

---

## 🚀 Project Overview

**pqbit** is a Python security and networking library that combines cutting-edge technologies to create a resilient, distributed, post-quantum digital infrastructure. It is designed for researchers, engineers, and enthusiasts seeking to build secure and intelligent systems with complete control.

---

## 🧩 Key Components

- 🔐 **Post-Quantum Security**  
  Uses algorithms such as Kyber1024 and Falcon1024 for quantum-resistant key exchange and digital signatures.

- 🕸️ **Intelligent Mesh Network**  
  Automatic configuration of WireGuard tunnels between multiple nodes with mesh topology and least privilege.

- 🔭 **Distributed Authentication**  
  Each node signs its identity with Falcon and validates peers before accepting packets, ensuring end-to-end trust.

- 🧬 **Adaptive Routing**  
  Dynamic neighbor selection based on traffic entropy and latency, prioritizing security and performance.

- 🛰️ **Encrypted Broadcast**  
  Discovery messages are encapsulated with Kyber and can only be decrypted by authorized nodes.

- 📊 **Adaptive Monitoring**  
  Interactive dashboard with real-time visualization of entropy, latency, authentication, and events.

---

## 📦 Objective

To offer a lightweight, auditable, and ready-to-use library for integrating quantum security with decentralized networks like Bit512.

Inspired by the [PQClean](https://github.com/PQClean/PQClean) project and integrated with anonymity technologies like Obfs4, WireGuard, and PySocks.

---

## 🔐 Supported Algorithms and Technologies

📄 `pqbit/simulation.py`  
✅ Integrated with `__init__.py` and `test_repository.py`  
🧠 Simulates key generation, encapsulation, and decapsulation using `secrets.token_bytes()`

- **Kyber1024** — Quantum-resistant KEM  
- **Dilithium5** — High-security post-quantum digital signatures  
- **Falcon1024** — Compact and efficient signatures for restricted environments  
- **Obfs4** — Traffic cloaking for anonymous networks  
- **WireGuard** — Lightweight and secure VPN  
- **PySocks** — SOCKS proxy for flexible traffic routing  
- **PQClean** — Clean C implementations for post-quantum security  
- **Wireshark (via PyShark)** — Deep packet inspection and live traffic analysis

---

## 📁 Module Overview

### ✅ `benchmark.py`  
Performance tests for cryptographic operations and network latency.

### ✅ `benchmark_routes.py`  
Benchmarks across multiple routing paths, measuring entropy and cloaking.

### ✅ `dilithium.py`  
Post-quantum digital signatures using Dilithium5.

### ✅ `falcon.py`  
Compact and efficient signatures with Falcon1024.

### ✅ `guardian.py`  
Node validation, audit logging, and peer authentication.

### ✅ `__init__.py`  
Centralized imports, versioning, and API exposure.

### ✅ `kyber.py`  
Quantum-resistant key encapsulation with Kyber1024.

### ✅ `log_benchmark.py`  
Structured logging of benchmark results and metrics.

### ✅ `log_viewer.py`  
Real-time visualization of logs: latency, entropy, and events.

### ✅ `mesh.yaml`  
Network topology configuration for mesh routing.

### ✅ `obfs4.py`  
Traffic cloaking via `obfs4proxy`, with port and cert support.

### ✅ `pqclean.py`  
Integration with PQClean C implementations via `ctypes`.

### ✅ `pysocks.py`  
SOCKS proxy setup for flexible routing and anonymity.

### ✅ `report.py`  
Audit reports and peer validation summaries.

### ✅ `tunnel.py`  
WireGuard tunnel lifecycle management and config validation.

### ✅ `verifier.py`  
Signature verification and peer identity checks.

### ✅ `wg-meshconf.py`  
Generates WireGuard mesh configs from `mesh.yaml`.

### ✅ `wireguard.py`  
Low-level WireGuard interface and tunnel orchestration.

### ✅ `wireshark.py`  
Packet capture and analysis using PyShark and Scapy.

---

## 📦 Installation

```bash
pip install pqbit
```

---

## 🤝 Contributing

Contributions are welcome! Fork the repository, open issues, and submit pull requests to help evolve Bit512.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Gratitude

This project is dedicated to the Python community and to those who believe in digital freedom.
```

---

