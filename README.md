## 🧠 pqbit

![Banner pqbit v1.2.0](assets/banner.png)
![PyPI](https://img.shields.io/pypi/v/pqbit)
![License](https://img.shields.io/github/license/kitohamachi/pqbit)
![Build](https://img.shields.io/github/actions/workflow/status/kitohamachi/pqbit/python-app.yml)
![Coverage](https://img.shields.io/codecov/c/github/kitohamachi/pqbit)

Post-quantum mesh VPN library with WireGuard, PQClean, Pyshark, Scapy, and Logging4 — built for Bit512.

---

**Author**: Kito Hamachi — Bit512 Labs  
**License**: MIT  
**Repository**: [github.com/kitohamachi/pqbit](https://github.com/kitohamachi/pqbit)  
**PyPI**: [pypi.org/project/pqbit](https://pypi.org/project/pqbit)

---

## 📦 Installation

```bash
pip install pqbit
```

---

## 🔍 Features

- 🔐 **Post-Quantum Cryptography**: Kyber1024, Dilithium5, Falcon1024 via PQClean

- 🕸️ **Mesh VPN**: WireGuard tunnels with automatic peer discovery and config

- 🛰️ **Encrypted Broadcast**: Kyber-encrypted discovery messages

- 🧬 **Adaptive Routing**: Based on entropy and latency

- 🧭 **Distributed Authentication**: Falcon-signed peer validation

- 🕵️ **Traffic Cloaking**: Obfs4 + PySocks integration

- 📊 **Live Monitoring**: Real-time entropy, latency, and event logs via PyShark

- 🔑 **Offline Wallets**: SHA3-512 + Dilithium5 for post-quantum identity generation

---

## 🧪 Usage Examples

### 🔐 Falcon Signature

```python
from pqbit import falcon_keypair, falcon_sign, falcon_verify

pk, sk = falcon_keypair()
message = b"Bit512 integrity test"
signature = falcon_sign(message, sk)

if falcon_verify(message, signature, pk):
    print("Signature verified ✅")
```

### 🔑 Wallet Generation (pqbit 1.2.0+)

```python
from pqbit import generate_wallet, verify_wallet

wallet = generate_wallet()
print("Fingerprint:", wallet["public_key"])
print("Verificado:", verify_wallet(wallet))
```

---

## 🧩 Key Components

- 🔐 **Post-Quantum Cryptography**  
  Kyber1024, Dilithium5, and Falcon1024 for quantum-resistant key exchange and digital signatures.

- 🕸️ **Mesh VPN Architecture**  
  WireGuard tunnels with automatic peer discovery, namespace support, and adaptive topology.

- 🔭 **Distributed Authentication**  
  Falcon-signed node identities with peer verification and audit logging.

- 🔑 **Offline Wallets (v1.2.0+)**  
  36-word seed phrases hashed with SHA3-512 and signed using Dilithium5. Enables portable, verifiable, post-quantum identities without exposing raw keys.

- 🛰️ **Encrypted Broadcast Channels**  
  Kyber-encrypted discovery packets for secure mesh initialization and peer signaling.

- 🧬 **Entropy-Based Routing**  
  Peer selection based on real-time entropy and latency metrics, optimizing for security and performance.

- 🕵️ **Traffic Cloaking & Proxying**  
  Obfs4 integration with PySocks for stealth routing and anonymous overlays.

- 📊 **Live Monitoring & Inspection**  
  Real-time packet analysis, entropy tracking, and event visualization via PyShark and Scapy.

---

## 📁 Modules Overview

### ✅ `benchmark.py`  
Performs cryptographic performance tests across Kyber, Falcon, and Dilithium. Measures key generation time, signature throughput, and latency under simulated load.

### ✅ `benchmark_routes.py`  
Evaluates routing performance across mesh paths. Calculates entropy, latency, and cloaking efficiency using synthetic traffic and randomized peer selection.

### ✅ `dilithium.py`  
Implements Dilithium5 digital signatures via PQClean. Used for signing messages, identities, and wallet digests with post-quantum security guarantees.

### ✅ `falcon.py`  
Provides Falcon1024 signature generation and verification. Optimized for constrained environments and used in peer authentication.

### ✅ `guardian.py`  
Core module for node validation and distributed trust. Handles peer audits, identity signing, entropy scoring, and latency-based selection.

### ✅ `__init__.py`  
Exposes the public API of `pqbit`. Centralizes imports, versioning, and module registration for PyPI and internal use.

### ✅ `kyber.py`  
Handles Kyber1024 key encapsulation and decapsulation. Used for encrypted broadcast, peer discovery, and secure tunnel initialization.

### ✅ `log_benchmark.py`  
Captures structured logs from benchmarking modules. Supports JSON output, timestamping, and integration with external log viewers.

### ✅ `log_viewer.py`  
Interactive CLI or GUI tool for visualizing logs. Displays entropy trends, latency spikes, and authentication events in real time.

### ✅ `mesh.yaml`  
Declarative configuration file for mesh topology. Defines peers, routes, namespaces, and tunnel parameters for WireGuard orchestration.

### ✅ `obfs4.py`  
Wraps `obfs4proxy` for traffic cloaking. Supports certificate pinning, port randomization, and stealth routing for anonymous overlays.

### ✅ `pqclean.py`  
Provides low-level bindings to PQClean C implementations via `ctypes`. Enables direct access to Kyber, Falcon, and Dilithium primitives.

### ✅ `pysocks.py`  
Sets up SOCKS proxies for flexible routing. Integrates with WireGuard and Obfs4 to support layered anonymity and traffic redirection.

### ✅ `report.py`  
Generates audit reports from peer validation and guardian logs. Summarizes trust scores, signature integrity, and routing performance.

### ✅ `tunnel.py`  
Manages WireGuard tunnel lifecycle. Validates configs, applies namespaces, and monitors tunnel health across mesh nodes.

### ✅ `verifier.py`  
Verifies digital signatures and peer identities. Used during handshake, broadcast validation, and audit replay.

### ✅ `wg-meshconf.py`  
Generates WireGuard configuration files from `mesh.yaml`. Supports multi-peer setups, namespace isolation, and adaptive routing hints.

### ✅ `wireguard.py`  
Low-level interface to WireGuard. Handles key generation, tunnel setup, peer registration, and config synchronization.

### ✅ `wireshark.py`  
Captures and analyzes packets using PyShark and Scapy. Tracks entropy, latency, and cloaking effectiveness across mesh traffic.

### ✅ `wallet.py`  
Generates offline post-quantum wallets using 36-word seed phrases. Hashes seed with SHA3-512, signs digest with Dilithium5, and outputs a verifiable identity fingerprint. Includes signature verification logic for integrity checks.

---

## 📖 Table of Contents

- [📦 Installation](#-installation)

- [🧪 Usage Examples](#-usage-examples)
  - [🔐 Falcon Signature](#-falcon-signature)
  - [🔑 Wallet Generation (pqbit-120)](#-wallet-generation-pqbit-120)
  
- [🧩 Key Components](#-key-components)

- [📦 Objective](#-objective)

- [🔐 Supported Algorithms and Technologies](#-supported-algorithms-and-technologies)

- [📁 Module Overview](#-module-overview)

- [🤝 Contributing](#-contributing)

- [📜 License](#-license)

- [🙏 Gratitude](#-gratitude)

---

## 🚀 Project Overview

**pqbit** is a modular Python library for building secure, decentralized, and post-quantum digital infrastructure. It combines cryptographic primitives, mesh networking, traffic cloaking, and offline identity generation into a unified toolkit designed for resilience and autonomy.

Built for researchers, engineers, and privacy advocates, `pqbit` empowers users to:

- 🔐 Generate and verify post-quantum keys and signatures using Kyber, Dilithium, and Falcon
- 🕸️ Deploy adaptive WireGuard mesh networks with entropy-based routing and namespace isolation
- 🛰️ Broadcast encrypted discovery messages across cloaked overlays using Obfs4 and PySocks
- 🔑 Create offline wallets with SHA3-512 fingerprints and Dilithium-signed seed phrases
- 📊 Monitor traffic entropy, latency, and peer trust in real time via PyShark and Scapy

Whether you're prototyping quantum-safe VPNs, auditing peer identities, or building sovereign mesh systems, `pqbit` gives you full control over every cryptographic and network layer — with zero reliance on centralized infrastructure.

---

## 📦 Objective

To offer a lightweight, auditable, and ready-to-use library for integrating quantum security with decentralized networks like Bit512.

Inspired by the [PQClean](https://github.com/PQClean/PQClean) project and integrated with anonymity technologies like Obfs4, WireGuard, and PySocks.

---

## 🔐 Supported Algorithms and Technologies

📄 `pqbit/simulation.py`

📄 `pqbit/wallet.py`

✅ Integrated with `__init__.py`, `test_repository.py`, and `wallet.py`

🧠 Simulates key generation, encapsulation, signing, and verification using `secrets.token_bytes()` and 36-word seed phrases

- **Kyber1024** — Quantum-resistant key encapsulation (KEM)
- **Dilithium5** — High-security post-quantum digital signatures (used in wallet signing)
- **Falcon1024** — Compact and efficient signatures for constrained environments
- **SHA3-512** — Cryptographic hashing for seed digest and public key fingerprinting
- **Obfs4** — Traffic cloaking for anonymous networks
- **WireGuard** — Lightweight and secure VPN tunneling
- **PySocks** — SOCKS proxy for flexible traffic routing
- **PQClean** — Clean C implementations for post-quantum cryptography
- **Wireshark (via PyShark)** — Deep packet inspection and live traffic analysis

---

## 🤝 Contributing

Contributions are welcome! Fork the repository, open issues, and submit pull requests to help evolve Bit512.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Gratitude

Inspired by [PQClean](https://github.com/PQClean/PQClean) and dedicated to the open-source security community.

This project is dedicated to the Python community and to those who believe in digital freedom.

<p align="center">
  <img src="assets/banner.png" alt="pqbit — Post-Quantum Wallet" width="600"/>
</p>
