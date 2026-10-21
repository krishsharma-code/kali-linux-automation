#!/bin/bash

# Untrusted PPA Purger
# Scans system source listings, verifying cryptographic signatures of active package distributors.

echo "=== Untrusted PPA & Repo Purger ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root." 
   exit 1
fi

echo "[*] Listing active third-party repositories..."
find /etc/apt/sources.list.d/ -type f -name "*.list"

echo "[*] Verifying repository signatures..."
# apt-key is deprecated, using /etc/apt/trusted.gpg.d/ and signed-by
# In a real Kali setup, we'd check for non-kali.org domains
SUSPICIOUS=$(grep -v "kali.org" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -v "^#" | awk -F: '{print $1}' | sort -u)

if [[ -n "$SUSPICIOUS" ]]; then
    echo "[!] WARNING: Found non-standard repositories:"
    echo "$SUSPICIOUS"
    
    # Prompt for purging (Mock)
    # echo "[?] Would you like to purge untrusted sources? (y/n)"
    # read -r choice
    echo "[*] Recommendation: Review the above files and remove any unknown third-party PPAs."
else
    echo "[+] All repositories appear to be standard Kali/Debian sources."
fi

# Refresh package lists to check for key errors
echo "[*] Refreshing package cache to verify keys..."
apt-get update -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false
