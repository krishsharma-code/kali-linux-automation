#!/bin/bash
# 10_process_hunter.sh
# Uses 'ps aux' and 'grep' to find running processes.

# Example: searching for the current bash shell process
PROCESS_NAME="bash"

echo "[*] Searching for processes related to: $PROCESS_NAME"

# 'ps aux' lists all running processes in detail
# Piped to 'grep' to filter for the specific process name
# 'grep -v grep' excludes the grep command itself from results
ps aux | grep "$PROCESS_NAME" | grep -v "grep"

echo "[+] Process hunt completed."
