#!/bin/bash
# 90_clear_logs_simulator.sh
# Day 11: Local Enumeration (Anti-Forensics Awareness)
# Description: Demonstrates how threat actors clear logs, strictly for defensive understanding.

echo "[!!!] FOR EDUCATIONAL AND DEFENSIVE PURPOSES ONLY [!!!]"
echo "[*] Understanding how attackers cover their tracks is key to effective incident response."
echo "---------------------------------------------------------------------------------"

# 1. Clearing Bash History
# This is often done to hide commands executed during a breach.
echo "[i] Method 1: Clearing current session history and history file."
# history -c clears the current session history
# history -w writes the (now empty) history to the file
echo "    Commands: history -c && history -w"

# 2. Wiping /var/log/wtmp (login records)
echo "[i] Method 2: Truncating login logs (wtmp, utmp, lastlog)."
echo "    Command: echo > /var/log/wtmp"

# 3. Securely deleting files
if command -v shred &>/dev/null; then
    echo "[i] Method 3: Using 'shred' to overwrite a file multiple times."
    echo "    Command: shred -u suspicious_file.txt"
else
    echo "[i] Method 3: Using 'dd' to overwrite with zeros if shred is missing."
    echo "    Command: dd if=/dev/zero of=suspicious_file.txt bs=1M count=1"
fi

echo "---------------------------------------------------------------------------------"
echo "[!] DEFENSIVE TIP: Use centralized logging (SIEM) and immutable log servers to"
echo "    ensure attackers cannot delete evidence of their activities."
