#!/bin/bash
# 27_find_suid_binaries.sh
# Day 5: Security Auditing & System Defense
# Description: Locates files with SUID or SGID bits set (potential privesc vectors).

echo "[*] Searching for SUID/SGID binaries on the system..."
echo "[*] This may take a moment depending on disk size..."
echo "--------------------------------------------------------"

# -perm /4000 looks for SUID
# -perm /2000 looks for SGID
# 2>/dev/null hides permission denied errors

echo "[+] SUID Files (Set Owner User ID):"
find / -perm /4000 -type f 2>/dev/null | xargs ls -lh

echo ""
echo "[+] SGID Files (Set Group ID):"
find / -perm /2000 -type f 2>/dev/null | xargs ls -lh

echo "--------------------------------------------------------"
echo "[*] Audit complete. Review the above files for unusual or unauthorized binaries."
