#!/bin/bash

# Basic DNS Enumeration Script
# Forward and Reverse lookups

if [ -z "$1" ]; then
    echo "Usage: $0 <domain_or_ip>"
    exit 1
fi

TARGET=$1

echo "[*] Performing DNS enumeration for $TARGET..."

echo -e "\n--- Forward Lookup ---"
host $TARGET

echo -e "\n--- NS Records ---"
dig $TARGET ns +short

echo -e "\n--- MX Records ---"
dig $TARGET mx +short

echo -e "\n--- Reverse Lookup (if IP) ---"
if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    dig -x $TARGET +short
else
    echo "[!] Skip reverse lookup (not an IP)."
fi
