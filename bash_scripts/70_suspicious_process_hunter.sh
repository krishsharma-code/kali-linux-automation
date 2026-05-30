#!/bin/bash
# 70_suspicious_process_hunter.sh - Scans for high resource or suspicious paths.
# Day 9: Forensics and Hardening

echo "--- Suspicious Process Hunter ---"

# 1. Look for high CPU consumers (> 10%)
echo -e "\n--- High CPU Processes (>10%) ---"
ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | awk '$4 > 10.0 {print $0}'

# 2. Look for processes running from /tmp or /dev/shm (Common for malware)
echo -e "\n--- Processes running from volatile paths (/tmp, /dev/shm) ---"
ps -eo pid,cmd | grep -E "/tmp/|/dev/shm/" | grep -v grep

# 3. Look for hidden processes (leading dots)
echo -e "\n--- Hidden Process Binaries ---"
ps -eo pid,cmd | grep -E "/\." | grep -v grep

echo -e "\nScan Complete."
