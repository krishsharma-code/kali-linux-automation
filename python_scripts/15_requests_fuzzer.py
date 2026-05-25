#!/usr/bin/env python3
"""
15_requests_fuzzer.py
Concept: Basic directory fuzzing using Python requests.
Description: Checks for the existence of directories on a target web server using a wordlist.
"""

import requests
import sys

def fuzz(url, wordlist):
    print(f"[*] Starting fuzzing on: {url}")
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                word = line.strip()
                target_url = f"{url}/{word}"
                response = requests.get(target_url)
                
                if response.status_code == 200:
                    print(f"[+] Found: {target_url} (200 OK)")
                elif response.status_code == 403:
                    print(f"[-] Forbidden: {target_url} (403)")
                    
    except FileNotFoundError:
        print(f"[!] Error: Wordlist '{wordlist}' not found.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <wordlist>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    wordlist_path = sys.argv[2]
    fuzz(target_url, wordlist_path)
