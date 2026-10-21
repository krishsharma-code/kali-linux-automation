#!/usr/bin/env python3
"""
Day 8: HTTP Header Analyzer
Author: Senior Cybersecurity Instructor
Description: Fetches HTTP headers from a target to identify server version and security headers.
"""

import requests
import sys

def analyze_headers(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
            
        print(f"[*] Analyzing headers for: {url}")
        response = requests.get(url, timeout=5)
        headers = response.headers

        print("\n[+] Raw Headers:")
        for key, value in headers.items():
            print(f"    {key}: {value}")

        print("\n[+] Security Analysis:")
        security_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        for sh in security_headers:
            if sh in headers:
                print(f"    [PASS] {sh} is present.")
            else:
                print(f"    [FAIL] {sh} is missing!")

        server = headers.get('Server', 'Not disclosed')
        print(f"\n[+] Server Information: {server}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    analyze_headers(target)
