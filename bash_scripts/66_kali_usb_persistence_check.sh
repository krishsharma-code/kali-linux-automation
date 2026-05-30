#!/bin/bash
# 66_kali_usb_persistence_check.sh - Verifies health of persistent Kali USB.
# Day 9: Forensics and Hardening

echo "--- Kali Linux Persistence Health Check ---"

# Check for persistence partition (usually labeled 'persistence')
PERSISTENCE_PART=$(lsblk -o NAME,LABEL,SIZE | grep -i "persistence")

if [ -z "$PERSISTENCE_PART" ]; then
    echo "[!] Error: No partition with label 'persistence' found."
    echo "[*] Ensure your 256GB USB drive is connected and correctly labeled."
else
    echo "[OK] Persistence partition located:"
    echo "$PERSISTENCE_PART"
fi

# Check mount status
MOUNT_STATUS=$(mount | grep "persistence")
if [ -n "$MOUNT_STATUS" ]; then
    echo "[OK] Persistence is currently MOUNTED."
else
    echo "[WARN] Persistence partition is NOT mounted."
fi

# Disk usage check
echo -e "\n--- Storage Usage ---"
df -h | grep -E "Filesystem|persistence"
