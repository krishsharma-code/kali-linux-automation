#!/bin/bash
# nikto_fast_scan.sh
# Concept: Wrapper to run Nikto web scanner.
# Description: Automates a basic Nikto scan for vulnerabilities and misconfigurations.

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 0
fi

URL=$1

echo "[*] Launching Nikto scan against: $URL"

# Check if nikto is installed
if ! command -v nikto &> /dev/null; then
    echo "[!] nikto is not installed. Install via apt to use full features."
    exit 0
fi

nikto -h "$URL" -Tuning 123489
