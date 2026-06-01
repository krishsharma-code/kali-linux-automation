#!/bin/bash
# 86_suid_binary_finder.sh
# Day 11: Local Enumeration
# Description: Finds all files on the system with the SUID bit set and saves the list.

OUTPUT_FILE="suid_binaries.txt"

echo "[*] Scanning for SUID binaries... This may take a minute."
echo "[*] SUID bit allows a user to run an executable with the permissions of the executable's owner."

# Find command:
# / - start from root
# -perm -u=s - find files with SUID bit
# -type f - search for files only
# 2>/dev/null - hide error messages (e.g., Permission denied)
find / -perm -u=s -type f 2>/dev/null > "$OUTPUT_FILE"

COUNT=$(wc -l < "$OUTPUT_FILE")

echo "[+] Scan complete. Found $COUNT SUID binaries."
echo "[+] List saved to: $OUTPUT_FILE"
echo "[!] Review this list for unusual binaries that could be exploited for privilege escalation."
