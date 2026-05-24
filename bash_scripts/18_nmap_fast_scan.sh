#!/bin/bash

# 18_nmap_fast_scan.sh
# Concept: Automating a fast Nmap scan via Bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "[*] Initializing fast scan on $TARGET..."
echo "[*] Command: nmap -F $TARGET"

# -F scans top 100 ports
nmap -F "$TARGET"

echo "[+] Fast scan finalized."
