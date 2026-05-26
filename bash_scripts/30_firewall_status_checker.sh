#!/bin/bash
# 30_firewall_status_checker.sh
# Day 5: Security Auditing & System Defense
# Description: Checks status and rules for UFW and Iptables.

echo "[*] Auditing Firewall Status..."
echo "--------------------------------------------------------"

# Check UFW (Uncomplicated Firewall)
if command -v ufw >/dev/null 2>&1; then
    echo "[+] UFW (Uncomplicated Firewall) Status:"
    ufw status verbose
else
    echo "[!] UFW is not installed."
fi

echo ""

# Check Iptables
if command -v iptables >/dev/null 2>&1; then
    echo "[+] Iptables Active Rules (Filter Table):"
    iptables -L -n -v | head -n 20
    echo "... (truncated output)"
else
    echo "[!] Iptables command not found."
fi

echo "--------------------------------------------------------"
echo "[*] Firewall Audit complete. Ensure 'Default Deny' is applied to incoming traffic."
