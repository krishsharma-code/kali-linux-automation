#!/bin/bash
# 23_nikto_fast_scan.sh
# Concept: Wrapper to run Nikto web scanner.
# Description: Automates a basic Nikto scan for vulnerabilities and misconfigurations.

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

URL=$1

echo "[*] Launching Nikto scan against: $URL"

# Check if nikto is installed
if ! command -v nikto &> /dev/null; then
    echo "[!] Error: nikto is not installed."
    exit 1
fi

nikto -h "$URL" -Tuning 123489
