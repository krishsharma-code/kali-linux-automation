#!/bin/bash

# Quick Nmap Scan Wrapper
# Fast scan of the top 100 common ports

if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TARGET=$1

echo "[*] Starting quick Nmap scan on $TARGET..."
nmap -F --open $TARGET
