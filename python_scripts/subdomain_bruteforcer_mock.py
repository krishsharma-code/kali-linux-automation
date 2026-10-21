#!/usr/bin/env python3
"""
Day 8: Subdomain Bruteforcer (Mock/Safety First)
Author: Senior Cybersecurity Instructor
Description: Tests common subdomains against a target domain using DNS resolution.
"""

import os
import socket
import sys

def bruteforce_subdomains(domain, wordlist):
    print(f"[*] Bruteforcing subdomains for: {domain}")
    found = []

    for sub in wordlist:
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] Found: {target} -> {ip}")
            found.append(target)
        except socket.gaierror:
            pass
    
    if not found:
        print("[-] No common subdomains resolved.")
    return found

if __name__ == "__main__":
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    # Small mock wordlist for demonstration
    common_subs = ["www", "mail", "dev", "test", "api", "staging", "blog"]
    if os.environ.get("AUDIT") == "1" or os.environ.get("CI") == "true":
        print("[*] Test mode (AUDIT/CI): skipping live DNS resolution.")
        print(f"[*] Would test {len(common_subs)} common subdomains for: {target_domain}")
        sys.exit(0)
    bruteforce_subdomains(target_domain, common_subs)
