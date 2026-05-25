#!/usr/bin/env python3
"""
19_web_crawler_basic.py
Concept: Extracting all href links from a webpage.
Description: Uses BeautifulSoup to find and list all outgoing and internal links from a target URL.
"""

import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

def crawl(url):
    print(f"[*] Crawling links from: {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        links = soup.find_all('a')
        print(f"[+] Found {len(links)} links:\n")
        
        found_links = set()
        for link in links:
            href = link.get('href')
            if href:
                # Resolve relative URLs
                full_url = urljoin(url, href)
                if full_url not in found_links:
                    print(f"[>] {full_url}")
                    found_links.add(full_url)
                    
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    crawl(sys.argv[1])
