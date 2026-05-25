#!/usr/bin/env python3
"""
17_http_header_analyzer.py
Concept: Extracting Server info and security headers.
Description: Analyzes HTTP headers for sensitive information and missing security configurations.
"""

import requests
import sys

def analyze_headers(url):
    print(f"[*] Analyzing headers for: {url}")
    try:
        response = requests.get(url)
        headers = response.headers
        
        print("\n--- Basic Info ---")
        print(f"Server: {headers.get('Server', 'Not Found')}")
        print(f"X-Powered-By: {headers.get('X-Powered-By', 'Not Found')}")
        
        print("\n--- Security Headers ---")
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        for sh in security_headers:
            status = "[+]" if sh in headers else "[-]"
            print(f"{status} {sh}: {headers.get(sh, 'MISSING')}")
            
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    analyze_headers(sys.argv[1])
