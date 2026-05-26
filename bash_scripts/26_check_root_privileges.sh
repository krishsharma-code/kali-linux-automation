#!/bin/bash
# 26_check_root_privileges.sh
# Day 5: Security Auditing & System Defense
# Description: Verifies if the script is running with root/sudo privileges.

echo "[*] Initializing Privilege Audit..."

if [[ $EUID -ne 0 ]]; then
   echo "[!] ERROR: This script must be run as root or with sudo."
   echo "[*] Current User: $(whoami)"
   echo "[*] Action Required: Re-run with 'sudo $0'"
   exit 1
else
   echo "[+] SUCCESS: Root privileges confirmed."
   echo "[*] System: $(hostname)"
   echo "[*] Kernel: $(uname -r)"
   echo "[*] Audit authorized."
fi
