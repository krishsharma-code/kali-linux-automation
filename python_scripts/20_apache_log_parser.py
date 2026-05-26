#!/usr/bin/env python3
"""
20_apache_log_parser.py
Day 5: Security Auditing & Log Analysis
Description: Parses Apache access logs to identify suspicious activity like 404/500 spikes.
"""

import re
from collections import Counter

# Path to the mock/live log file
LOG_FILE = "access.log"

def parse_logs():
    print(f"[*] Analyzing {LOG_FILE} for suspicious activity...")
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()
    except FileNotFoundError:
        print("[!] Access log not found. Generating sample data for demonstration...")
        logs = [
            '192.168.1.10 - - [26/May/2026:10:01:00] "GET /admin HTTP/1.1" 404 512',
            '192.168.1.12 - - [26/May/2026:10:02:00] "POST /login HTTP/1.1" 500 234',
            '192.168.1.10 - - [26/May/2026:10:03:00] "GET /config.php HTTP/1.1" 404 122',
            '192.168.1.15 - - [26/May/2026:10:04:00] "GET /index.html HTTP/1.1" 200 1240',
        ]

    error_codes = []
    ip_addresses = []

    for line in logs:
        # Regex to extract IP and Status Code
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?" \s*(\d{3})', line)
        if match:
            ip = match.group(1)
            status = match.group(2)
            ip_addresses.append(ip)
            if status in ['404', '500', '403']:
                error_codes.append((ip, status))

    print("\n[+] Error Code Distribution (Suspected Probing):")
    counts = Counter(error_codes)
    for (ip, code), count in counts.items():
        print(f"    - IP: {ip} | Status: {code} | Occurrences: {count}")

    print("\n[+] Top Requesting IPs:")
    for ip, count in Counter(ip_addresses).most_common(3):
        print(f"    - {ip}: {count} requests")

if __name__ == "__main__":
    parse_logs()
