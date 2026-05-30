#!/usr/bin/env python3
"""
63_packet_sniffer_scapy_basic.py - Captures and prints local network packets summary.
Day 9: Forensics and Hardening
Note: Requires scapy (pip install scapy) and root privileges.
"""

try:
    from scapy.all import sniff
except ImportError:
    print("Error: Scapy not found. Install it with 'pip install scapy'.")
    exit(1)

def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        proto = packet["IP"].proto
        print(f"[PACKET] {ip_src} -> {ip_dst} | Protocol: {proto}")

def start_sniffing():
    print("--- Starting Basic Packet Sniffer (Ctrl+C to stop) ---")
    # count=10 to stop after 10 packets for demo safety
    sniff(prn=packet_callback, filter="ip", count=10)

if __name__ == "__main__":
    # Running this on Windows/WSL might require extra setup, so we wrap it
    try:
        start_sniffing()
    except PermissionError:
        print("Error: Root/Administrator privileges required to sniff packets.")
    except Exception as e:
        print(f"An error occurred: {e}")
