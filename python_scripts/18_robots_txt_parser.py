#!/usr/bin/env python3
"""
18_robots_txt_parser.py
Concept: Script to fetch and parse disallowed paths in robots.txt.
Description: Retrieves robots.txt and extracts all 'Disallow' entries to find hidden directories.
"""

import requests
import sys

def parse_robots(url):
    if not url.endswith('/'):
        url += '/'
    robots_url = f"{url}robots.txt"
    
    print(f"[*] Fetching robots.txt from: {robots_url}")
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            print("[+] Successfully retrieved robots.txt\n")
            lines = response.text.split('\n')
            disallowed = [line.split(': ')[1].strip() for line in lines if line.startswith('Disallow')]
            
            if disallowed:
                print("--- Disallowed Paths ---")
                for path in sorted(set(disallowed)):
                    print(f"[!] {path}")
            else:
                print("[-] No Disallow entries found.")
        else:
            print(f"[-] robots.txt not found (Status: {response.status_code})")
            
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    parse_robots(sys.argv[1])
