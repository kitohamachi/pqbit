# pqbit/pqbit/wireshark.py

import logging
import subprocess
from scapy.all import rdpcap, Raw  # type: ignore
from math import log2
import os
from typing import List

logger = logging.getLogger("pqbit.wireshark")

def capture_traffic(interface: str = "tun0", duration: int = 30, output: str = "bit512_capture.pcap") -> None:
    """
    Captures traffic from the specified interface using tshark.
    """
    logger.info(f"Capturing traffic for {duration}s on interface {interface}...")
    try:
        subprocess.run([
            "sudo", "tshark",
            "-i", interface,
            "-w", output,
            "-a", f"duration:{duration}"
        ], check=True)
        logger.info(f"Capture saved in {output}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error capturing traffic with tshark: {e}")

def entropy(data: bytes) -> float:
    """
    Calculates the entropy of a block of data.

    Args:
        data (bytes): Raw byte data

    Returns:
        float: Entropy value
    """
    if not data:
        return 0
    freq = {b: data.count(b) for b in set(data)}
    total = len(data)
    return -sum((f / total) * log2(f / total) for f in freq.values())

def analyze_entropy(pcap_file: str = "bit512_capture.pcap") -> None:
    """
    Analyzes average entropy of captured packets.
    """
    if not os.path.exists(pcap_file):
        logger.warning(f"File {pcap_file} not found.")
        return

    logger.info(f"Analyzing packet entropy in {pcap_file}...")
    packets = rdpcap(pcap_file)
    entropies = []

    for i, pkt in enumerate(packets):
        if Raw in pkt:
            e = entropy(bytes(pkt[Raw]))
            entropies.append(e)
            logger.info(f"Packet {i}: Entropy = {e:.2f}")

    if entropies:
        avg = sum(entropies) / len(entropies)
        logger.info(f"Average entropy: {avg:.2f} bits/byte")
        if avg > 7.5:
            logger.info("Traffic looks obfuscated. No one will know what happened.")
        else:
            logger.warning("Traffic may be revealing patterns. Time to reinforce the obfuscation.")
    else:
        logger.warning("No packets with raw payload were found.")

def audit(interface: str = "tun0", duration: int = 30) -> None:
    """
    Performs entropy capture and analysis in sequence.
    """
    capture_traffic(interface=interface, duration=duration)
    analyze_entropy()
