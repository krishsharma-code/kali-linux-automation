#!/usr/bin/env python3
"""
21_failed_login_detector.py
Day 5: Security Auditing & Log Analysis
Description: Parses auth.log to detect brute-force SSH login attempts.
"""

import re
from collections import Counter

# Common auth log path on Debian/Ubuntu
AUTH_LOG = "/var/log/auth.log"

def detect_failed_logins():
    print(f"[*] Scanning {AUTH_LOG} for failed login attempts...")
    
    attempts = []
    
    try:
        with open(AUTH_LOG, 'r') as f:
            for line in f:
                if "Failed password" in line:
                    # Extract IP address from the line
                    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        attempts.append(match.group(1))
    except FileNotFoundError:
        print("[!] /var/log/auth.log not found. Using simulation data...")
        attempts = ["10.0.0.5", "10.0.0.5", "10.0.0.5", "192.168.1.100", "10.0.0.5"]

    counts = Counter(attempts)
    
    print("\n[!] SUSPICIOUS ACTIVITY DETECTED:")
    print("-" * 40)
    for ip, count in counts.items():
        if count >= 3:
            status = "CRITICAL" if count > 5 else "WARNING"
            print(f"[{status}] IP {ip} failed {count} login attempts.")
        else:
            print(f"[INFO] IP {ip} failed {count} login attempts.")

if __name__ == "__main__":
    detect_failed_logins()
