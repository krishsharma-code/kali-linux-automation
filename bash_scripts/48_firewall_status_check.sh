#!/bin/bash

# 48_firewall_status_check.sh
# Checks UFW/iptables status and dumps current rules to a secure log.
# Part of Day 7: Defensive Monitoring

LOG_FILE="firewall_audit_$(date +%F).log"

echo "[*] Auditing Firewall Configuration..."
echo "[*] Log File: $LOG_FILE"
echo "--------------------------------------------------"

echo "--- UFW Status ---" | tee -a "$LOG_FILE"
if command -v ufw &> /dev/null; then
    sudo ufw status verbose | tee -a "$LOG_FILE"
else
    echo "UFW not installed." | tee -a "$LOG_FILE"
fi

echo -e "\n--- IPTables Rules ---" | tee -a "$LOG_FILE"
sudo iptables -L -n -v | tee -a "$LOG_FILE"

echo "--------------------------------------------------"
echo "[SUCCESS] Firewall status captured in $LOG_FILE"
