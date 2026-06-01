#!/bin/bash
# 89_system_info_gatherer.sh
# Day 11: Local Enumeration
# Description: Collects kernel version, hostname, and OS release info into a single recon file.

RECON_FILE="system_recon_$(date +%F).txt"

echo "[*] Gathering system information..."

{
    echo "=== System Reconnaissance Report ==="
    echo "Date: $(date)"
    echo "------------------------------------"
    echo "Hostname: $(hostname)"
    echo "User:     $USER"
    echo "Kernel:   $(uname -a)"
    echo "Uptime:   $(uptime -p)"
    echo "------------------------------------"
    echo "OS Release Info:"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release
    else
        lsb_release -a 2>/dev/null || echo "N/A"
    fi
    echo "------------------------------------"
    echo "CPU Info:"
    lscpu | grep "Model name"
    echo "------------------------------------"
    echo "Memory Info:"
    free -h
} > "$RECON_FILE"

echo "[+] Recon file created: $RECON_FILE"
echo "[*] Use this information to identify potential kernel exploits or misconfigurations."
