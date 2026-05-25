#!/usr/bin/env python3
"""
16_subdomain_bruteforce.py
Concept: Checking a list of subdomains against a target.
Description: Brute-forces subdomains by resolving them and checking their HTTP response.
"""

import requests
import sys

def check_subdomains(domain, wordlist):
    print(f"[*] Brute-forcing subdomains for: {domain}")
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                sub = line.strip()
                target = f"http://{sub}.{domain}"
                try:
                    response = requests.get(target, timeout=3)
                    print(f"[+] Found: {target} (Status: {response.status_code})")
                except requests.ConnectionError:
                    pass
                except requests.Timeout:
                    pass
    except FileNotFoundError:
        print(f"[!] Wordlist '{wordlist}' not found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <domain> <wordlist>")
        sys.exit(1)
    
    domain = sys.argv[1]
    wordlist = sys.argv[2]
    check_subdomains(domain, wordlist)
