#!/bin/bash

# Day 10: Nikto Web Scanner Wrapper
# Automates Nikto scans against a target and saves output to a timestamped file.

TARGET_URL=$1

if [ -z "$TARGET_URL" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="nikto_scan_${TIMESTAMP}.log"

echo "[*] Initiating Nikto Web Scan on $TARGET_URL..."

# In a real environment:
# nikto -h "$TARGET_URL" -o "$LOG_FILE" -Format txt

# Mock output
echo "Nikto v2.1.6" > "$LOG_FILE"
echo "Target IP: 192.168.1.10" >> "$LOG_FILE"
echo "Target Hostname: $TARGET_URL" >> "$LOG_FILE"
echo "+ The anti-clickjacking X-Frame-Options header is not present." >> "$LOG_FILE"
echo "+ The X-XSS-Protection header is not defined." >> "$LOG_FILE"
echo "+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS" >> "$LOG_FILE"

echo "[+] Scan finished. Summary saved to $LOG_FILE"
tail -n 5 "$LOG_FILE"
