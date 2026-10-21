#!/bin/bash

# suid_guid_finder.sh
# Finds files with SUID/GUID bits set that could be privilege escalation risks.
# Part of Day 7: Defensive Monitoring

echo "[*] Auditing System for SUID/GUID Files..."
echo "[!] Warning: SUID/GUID files allow execution with owner/group privileges."
echo "--------------------------------------------------"

# -perm /4000 looks for SUID
# -perm /2000 looks for GUID
# 2>/dev/null hides permission denied errors for system dirs

# In test mode (AUDIT/CI set), limit the scan to a small subtree so it returns fast.
SCAN_ROOT="/"
if [ -n "${AUDIT:-}" ] || [ "${CI:-}" = "true" ]; then
    SCAN_ROOT="/usr/bin"
fi

echo "[+] SUID Files Found:"
find "$SCAN_ROOT" -perm /4000 -type f 2>/dev/null | xargs ls -lh 2>/dev/null

echo ""
echo "[+] GUID Files Found:"
find "$SCAN_ROOT" -perm /2000 -type f 2>/dev/null | xargs ls -lh 2>/dev/null

echo "--------------------------------------------------"
echo "[+] Audit Complete."
