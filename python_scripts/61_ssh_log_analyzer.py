#!/usr/bin/env python3
"""
61_ssh_log_analyzer.py - Parses a mock auth.log to extract failed SSH login IPs.
Day 9: Forensics and Hardening
"""

import re
from collections import Counter

# Mock log data representing /var/log/auth.log
MOCK_AUTH_LOG = """
May 30 10:00:01 kali sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2
May 30 10:00:05 kali sshd[1234]: Failed password for admin from 192.168.1.50 port 54322 ssh2
May 30 10:00:10 kali sshd[1234]: Failed password for root from 192.168.1.50 port 54323 ssh2
May 30 10:05:01 kali sshd[1235]: Failed password for user1 from 10.0.0.15 port 43210 ssh2
May 30 10:06:01 kali sshd[1236]: Accepted password for krish from 192.168.1.10 port 22 ssh2
"""

def analyze_ssh_log(log_content):
    # Regex to find IP addresses in failed password attempts
    failed_attempts = re.findall(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", log_content)
    
    counts = Counter(failed_attempts)
    
    print("--- Failed SSH Login Report ---")
    for ip, count in counts.items():
        status = "[ALERT]" if count > 2 else "[INFO]"
        print(f"{status} IP: {ip} | Attempts: {count}")

if __name__ == "__main__":
    analyze_ssh_log(MOCK_AUTH_LOG)
