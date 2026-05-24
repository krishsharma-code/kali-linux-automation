#!/usr/bin/env python3
import subprocess
import sys

# 10_nmap_subprocess_wrapper.py
# Concept: Using Python to automate external security tools (Nmap)

def run_nmap(target):
    print(f"[*] Starting Nmap scan on target: {target}")
    try:
        # We use subprocess.run to execute the external nmap command.
        # -F is for 'Fast' mode (scans top 100 ports).
        result = subprocess.run(['nmap', '-F', target], capture_output=True, text=True, check=True)
        print("[+] Scan Results:\n")
        print(result.stdout)
    except FileNotFoundError:
        print("[!] Error: Nmap is not installed or not in PATH.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: Nmap scan failed. {e}")

if __name__ == "__main__":
    target_ip = input("Enter target IP or hostname (e.g., 127.0.0.1): ") or "127.0.0.1"
    run_nmap(target_ip)
