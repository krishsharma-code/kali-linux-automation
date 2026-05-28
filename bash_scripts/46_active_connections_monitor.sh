#!/bin/bash

# 46_active_connections_monitor.sh
# Uses netstat or ss to list established connections and their PIDs.
# Part of Day 7: Defensive Monitoring

echo "[*] Monitoring Active Network Connections..."
echo "--------------------------------------------------"
printf "%-20s %-20s %-10s %-10s\n" "Local Address" "Foreign Address" "State" "PID/Program"

# Check if 'ss' is available (modern replacement for netstat)
if command -v ss &> /dev/null; then
    # -n (numeric), -t (tcp), -u (udp), -p (processes), -a (all)
    # Filtering for ESTABLISHED state
    ss -ntupa | grep "ESTAB" | awk '{printf "%-20s %-20s %-10s %-10s\n", $5, $6, $1, $7}'
else
    # Fallback to netstat
    netstat -ntp | grep "ESTABLISHED" | awk '{printf "%-20s %-20s %-10s %-10s\n", $4, $5, $6, $7}'
fi

echo "--------------------------------------------------"
echo "[+] Scan Complete."
