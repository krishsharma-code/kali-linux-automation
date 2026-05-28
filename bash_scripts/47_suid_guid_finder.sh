#!/bin/bash

# 47_suid_guid_finder.sh
# Finds files with SUID/GUID bits set that could be privilege escalation risks.
# Part of Day 7: Defensive Monitoring

echo "[*] Auditing System for SUID/GUID Files..."
echo "[!] Warning: SUID/GUID files allow execution with owner/group privileges."
echo "--------------------------------------------------"

# -perm /4000 looks for SUID
# -perm /2000 looks for GUID
# 2>/dev/null hides permission denied errors for system dirs

echo "[+] SUID Files Found:"
find / -perm /4000 -type f 2>/dev/null | xargs ls -lh 2>/dev/null

echo ""
echo "[+] GUID Files Found:"
find / -perm /2000 -type f 2>/dev/null | xargs ls -lh 2>/dev/null

echo "--------------------------------------------------"
echo "[+] Audit Complete."
