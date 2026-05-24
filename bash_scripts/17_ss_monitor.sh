#!/bin/bash

# 17_ss_monitor.sh
# Concept: Using the modern 'ss' (socket statistics) command

echo "[*] Analyzing socket statistics..."
echo "----------------------------------"

# ss is the modern replacement for netstat
# -a: all
# -t: tcp
# -4: IPv4

ss -at4 | column -t

echo "----------------------------------"
echo "[+] Analysis finished."
