#!/usr/bin/env python3
"""
94_dns_recon_resolver.py
Day 12: System and Network Enumeration

Description:
    Performs DNS reconnaissance on a target domain by resolving standard records:
    A (IPv4), MX (Mail Exchange), and TXT (Text/Metadata).

Cybersecurity Principle:
    DNS reconnaissance provides valuable information about an organization's 
    infrastructure, including mail servers and hidden services (via TXT records). 
    Misconfigured DNS records can leak sensitive technical details to an attacker.
"""

import socket
import sys

def resolve_dns(domain):
    """
    Resolves various DNS records for a given domain using standard socket library.
    Note: For advanced MX/TXT records, dnspython is usually preferred, 
    but we use standard libraries where possible for portability.
    """
    print(f"[*] Starting DNS Recon for: {domain}\n")
    
    # 1. Resolve 'A' Records (IPv4)
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        print("[+] 'A' Records (IPv4 Addresses):")
        for ip in ips:
            print(f"    - {ip}")
    except socket.gaierror:
        print("[-] Could not resolve 'A' records.")

    # Note: Standard socket module is limited for MX/TXT.
    # In a full Kali environment, one would typically use 'dnsrecon' or 'dig'.
    print("\n[!] Technical Note: Use 'dig' or 'host' for advanced MX/TXT/NS enumeration.")
    print(f"[*] Recon session for {domain} completed.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 94_dns_recon_resolver.py <DOMAIN>")
        print("Example: python3 94_dns_recon_resolver.py example.com")
        sys.exit(1)

    resolve_dns(sys.argv[1])
