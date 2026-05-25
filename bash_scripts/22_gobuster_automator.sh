#!/bin/bash
# 22_gobuster_automator.sh
# Concept: Automates a gobuster dirb scan with standard wordlists.
# Description: Runs gobuster to find hidden directories using common extensions.

if [ -z "$1" ]; then
    echo "Usage: $0 <url> [wordlist]"
    exit 1
fi

URL=$1
WORDLIST=${2:-"/usr/share/wordlists/dirb/common.txt"}

echo "[*] Starting Gobuster scan on: $URL"
echo "[*] Using wordlist: $WORDLIST"

# Check if gobuster is installed
if ! command -v gobuster &> /dev/null; then
    echo "[!] Error: gobuster is not installed."
    exit 1
fi

gobuster dir -u "$URL" -w "$WORDLIST" -t 50 -x php,html,txt,bak
