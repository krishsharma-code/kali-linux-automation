#!/bin/bash

# 16_netstat_active_ports.sh
# Concept: Filtering active listening services using netstat

echo "[*] Listing all active listening ports (TCP/UDP)..."
echo "--------------------------------------------------"

# -l: listening
# -t: tcp
# -u: udp
# -n: numeric addresses
# -p: show PID/Program name (requires sudo for all info)

netstat -ltunp 2>/dev/null | grep "LISTEN" || echo "[!] No active listening ports found or netstat not installed."

echo "--------------------------------------------------"
echo "[+] Scan complete."
