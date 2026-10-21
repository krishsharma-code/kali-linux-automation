#!/bin/bash
# Day 8: DNS Enumeration Tool
# Author: Senior Cybersecurity Instructor
# Description: Extracts A, MX, and TXT records for a domain.

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "[*] Enumerating DNS records for: $DOMAIN"

echo -e "\n[+] A Records:"
host -t A "$DOMAIN"

echo -e "\n[+] MX Records:"
host -t MX "$DOMAIN"

echo -e "\n[+] TXT Records:"
host -t TX "$DOMAIN"

echo -e "\n[+] Name Servers:"
host -t NS "$DOMAIN"

echo -e "\n[*] Full Dig Output (Short):"
dig "$DOMAIN" ANY +short
