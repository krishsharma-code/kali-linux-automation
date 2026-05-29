#!/usr/bin/env python3
"""
Day 8: Directory Fuzzer Lite
Author: Senior Cybersecurity Instructor
Description: Checks for common sensitive directories returning 200 OK.
"""

import requests
import sys

def fuzz_directories(url, wordlist):
    if not url.startswith('http'):
        url = 'http://' + url
    if not url.endswith('/'):
        url += '/'

    print(f"[*] Fuzzing directories on: {url}")
    
    for path in wordlist:
        target = f"{url}{path}"
        try:
            response = requests.get(target, timeout=3, allow_redirects=False)
            if response.status_code == 200:
                print(f"[+] FOUND: {target} (Status: 200)")
            elif response.status_code == 301 or response.status_code == 302:
                print(f"[*] REDIRECT: {target} -> {response.headers.get('Location')}")
        except requests.exceptions.RequestException:
            pass

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    # Basic wordlist
    dirs = ["admin", "login", "config", "api", "v1", "backup", "db", "uploads", "test"]
    fuzz_directories(target_url, dirs)
