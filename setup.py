# pqbit/setup.py

import os
from setuptools import setup, find_packages

# 📘 README.md
long_description = ""
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="pqbit",
    version="1.0.0",
    author="kitohamachi",
    author_email="kitohamachi@hotmail.com",
    description="Post-quantum mesh VPN library with WireGuard, PQClean, Pyshark, Scapy, and Logging4",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kitohamachi/pqbit",
    packages=find_packages(include=["pqbit", "pqbit.*"])
    include_package_data=True,
    install_requires=[
        "pypqc>=0.0.6.2",
        "pyshark>=0.6",
        "wg-meshconf>=2.5.1",
        "wireguard>=1.0.2",
        "wireguard4netns>=0.1.6",
        "scapy>=2.5.0",
        "cffi>=2.0.0",
        "pycparser>=2.23",
        "logging4>=0.0.2"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    keywords="wireguard, pqclean, post-quantum, vpn, mesh, cryptography, scapy, pyshark"
)

