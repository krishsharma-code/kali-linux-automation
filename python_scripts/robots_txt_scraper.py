#!/usr/bin/env python3
"""
Day 8: Robots.txt Scraper
Author: Senior Cybersecurity Instructor
Description: Downloads and parses robots.txt to identify disallowed directories.
"""

import requests
import sys
from urllib.parse import urljoin

def scrape_robots(url):
    if not url.startswith('http'):
        url = 'http://' + url
    
    robots_url = urljoin(url, '/robots.txt')
    print(f"[*] Fetching: {robots_url}")

    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            print("[+] robots.txt found! Disallowed paths:")
            lines = response.text.split('\n')
            for line in lines:
                if line.startswith('Disallow:'):
                    print(f"    {line}")
        elif response.status_code == 404:
            print("[-] robots.txt not found (404).")
        else:
            print(f"[-] Failed to fetch robots.txt (Status: {response.status_code})")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scrape_robots(target)
