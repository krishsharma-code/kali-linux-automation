#!/bin/bash
# 29_ssh_config_auditor.sh
# Day 5: Security Auditing & System Defense
# Description: Audits sshd_config for common security misconfigurations.

SSH_CONFIG="/etc/ssh/sshd_config"

echo "[*] Auditing SSH Daemon Configuration: $SSH_CONFIG"
echo "--------------------------------------------------------"

if [ ! -f "$SSH_CONFIG" ]; then
    echo "[!] ERROR: SSH config not found at $SSH_CONFIG"
    exit 1
fi

# Function to check specific settings
check_setting() {
    local setting=$1
    local expected=$2
    local actual=$(grep "^$setting" "$SSH_CONFIG" | awk '{print $2}')
    
    if [ -z "$actual" ]; then
        echo "[WARNING] $setting is not explicitly set (using default)."
    elif [ "$actual" == "$expected" ]; then
        echo "[OK] $setting is set to $actual."
    else
        echo "[!!!] RISK DETECTED: $setting is set to $actual (Recommended: $expected)."
    fi
}

check_setting "PermitRootLogin" "no"
check_setting "PasswordAuthentication" "no"
check_setting "PubkeyAuthentication" "yes"
check_setting "MaxAuthTries" "3"
check_setting "PermitEmptyPasswords" "no"

echo "--------------------------------------------------------"
echo "[*] SSH Audit complete. Follow best practices to harden your gateway."
