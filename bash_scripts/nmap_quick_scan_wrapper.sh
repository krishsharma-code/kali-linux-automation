#!/bin/bash
# Day 8: Nmap Quick Scan Wrapper
# Author: Senior Cybersecurity Instructor
# Description: Runs a fast port scan and saves results.

TARGET=$1
OUTPUT="scan_results_${TARGET//./_}.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
fi

echo "[*] Starting Nmap Quick Scan on $TARGET..."
# -F: Fast mode (scan fewer ports)
# -T4: Faster execution
# -oN: Normal output
nmap -F -T4 "$TARGET" -oN "$OUTPUT"

if [ $? -eq 0 ]; then
    echo "[+] Scan complete. Results saved to $OUTPUT"
else
    echo "[!] Nmap scan failed. Ensure nmap is installed."
fi
