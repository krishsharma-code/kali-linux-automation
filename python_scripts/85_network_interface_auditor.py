#!/usr/bin/env python3
"""
85_network_interface_auditor.py
Day 11: Local Enumeration
Description: Uses the os and subprocess modules to list active interfaces and check promiscuous mode.
"""

import subprocess
import os

def audit_interfaces():
    print("[*] Auditing Network Interfaces...")
    print("-" * 50)

    try:
        # Get interfaces using 'ip addr'
        result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("[-] Error: 'ip' command failed. Are you on Linux?")
            return

        lines = result.stdout.splitlines()
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 2:
                iface_name = parts[1].strip()
                details = parts[2].strip()
                
                status = "UP" if "UP" in details else "DOWN"
                promisc = "PROMISC" if "PROMISC" in details else "NORMAL"
                
                print(f"[+] Interface: {iface_name}")
                print(f"    Status: {status}")
                print(f"    Mode:   {promisc}")
                
                if promisc == "PROMISC":
                    print(f"    [!!!] WARNING: {iface_name} is in promiscuous mode (Potential Sniffing!)")
                print("-" * 30)

    except FileNotFoundError:
        print("[-] Error: 'ip' command not found. Ensure iproute2 is installed.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    audit_interfaces()
