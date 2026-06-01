#!/bin/bash
# 88_sudo_privilege_checker.sh
# Day 11: Local Enumeration
# Description: Automates running sudo -l and parsing the output for NOPASSWD entries.

echo "[*] Checking SUDO privileges for user: $USER"
echo "--------------------------------------------------------"

# Run sudo -l. Note: This may prompt for a password if not already cached.
SUDO_L_OUTPUT=$(sudo -l 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "[-] Error: Unable to run 'sudo -l'. User may not have sudo access or password is required."
    exit 1
fi

echo "$SUDO_L_OUTPUT"

echo "--------------------------------------------------------"
echo "[*] Analyzing output for high-risk configurations..."

# Check for NOPASSWD entries
if echo "$SUDO_L_OUTPUT" | grep -qi "NOPASSWD"; then
    echo "[!!!] CRITICAL: NOPASSWD entries found!"
    echo "$SUDO_L_OUTPUT" | grep -i "NOPASSWD"
else
    echo "[+] No NOPASSWD entries found in the current output."
fi

# Check for (ALL : ALL) ALL
if echo "$SUDO_L_OUTPUT" | grep -qi "(ALL : ALL) ALL"; then
    echo "[!] User has full sudo privileges (ALL:ALL) ALL."
fi

echo "--------------------------------------------------------"
echo "[*] Audit finished."
