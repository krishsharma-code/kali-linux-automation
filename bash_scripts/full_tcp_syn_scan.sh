#!/bin/bash

# Full TCP SYN Scan
# Stealthy scan of all 65535 ports (Requires sudo)

if [ "$EUID" -ne 0 ]; then
  echo "[!] This tool requires root privileges. Re-run with sudo."
  exit 0
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    exit 0
fi

TARGET=$1

echo "[*] Starting full SYN scan on all ports for $TARGET..."
nmap -sS -p- -T4 $TARGET
