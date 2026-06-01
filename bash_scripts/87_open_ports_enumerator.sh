#!/bin/bash
# 87_open_ports_enumerator.sh
# Day 11: Local Enumeration
# Description: Uses ss or netstat to list all listening ports and the associated PIDs.

echo "[*] Enumerating Listening Ports..."
echo "--------------------------------------------------------"
echo "Protocol  Local Address      PID/Program Name"
echo "--------------------------------------------------------"

# Check if 'ss' is available (modern replacement for netstat)
if command -v ss &>/dev/null; then
    # -l: listening
    # -n: numeric
    # -t: tcp
    # -u: udp
    # -p: process info
    ss -lnupt | grep -i "LISTEN"
else
    # Fallback to netstat
    netstat -lnupt | grep -i "LISTEN"
fi

echo "--------------------------------------------------------"
echo "[*] Audit complete. Check for unauthorized services on unexpected ports."
