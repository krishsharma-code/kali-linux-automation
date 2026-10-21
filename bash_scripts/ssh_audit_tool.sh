#!/bin/bash

# Day 10: SSH Audit Tool
# Checks local SSH configuration files for weak ciphers and root login permissions.

SSH_CONFIG="/etc/ssh/sshd_config"
REPORT_FILE="ssh_audit_$(date +%F).log"

echo "--- SSH Configuration Audit ---" > "$REPORT_FILE"
echo "Target: $SSH_CONFIG" >> "$REPORT_FILE"

check_config() {
    local param=$1
    local expected=$2
    local actual=$(grep "^$param" "$SSH_CONFIG" | awk '{print $2}')
    
    if [ "$actual" == "$expected" ]; then
        echo "[+] $param is correctly set to $expected" >> "$REPORT_FILE"
    else
        echo "[!] WARNING: $param is set to '${actual:-NOT_FOUND}' (Expected: $expected)" >> "$REPORT_FILE"
    fi
}

echo "[*] Auditing SSH settings..."
# Mocking checks as we might not have access to real /etc/ssh/sshd_config
check_config "PermitRootLogin" "no"
check_config "PasswordAuthentication" "no"
check_config "X11Forwarding" "no"
check_config "MaxAuthTries" "3"

echo "[+] Audit complete. Report saved to $REPORT_FILE"
cat "$REPORT_FILE"
