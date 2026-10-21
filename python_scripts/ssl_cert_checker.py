#!/usr/bin/env python3
"""
Day 8: SSL Certificate Checker
Author: Senior Cybersecurity Instructor
Description: Extracts SSL/TLS certificate info including expiration date.
"""

import socket
import ssl
import sys
from datetime import datetime

def check_ssl(hostname):
    port = 443
    context = ssl.create_default_context()

    try:
        print(f"[*] Connecting to {hostname} on port {port}...")
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract expiration date
                expiry_str = cert.get('notAfter')
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                
                print(f"[+] Certificate for: {hostname}")
                print(f"    Subject: {cert.get('subject')}")
                print(f"    Issuer: {cert.get('issuer')}")
                print(f"    Expires on: {expiry_date}")
                
                days_left = (expiry_date - datetime.utcnow()).days
                print(f"    Days remaining: {days_left}")

    except Exception as e:
        print(f"[!] SSL Check Failed: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    check_ssl(target)
