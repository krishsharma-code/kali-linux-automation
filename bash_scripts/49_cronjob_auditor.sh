#!/bin/bash

# 49_cronjob_auditor.sh
# Lists all scheduled cron jobs across all users to check for persistence.
# Part of Day 7: Defensive Monitoring

echo "[*] Auditing System Cron Jobs for Persistence..."
echo "--------------------------------------------------"

# System-wide cron files
echo "[+] System-wide Cron Files (/etc/crontab, /etc/cron.d/):"
ls -la /etc/crontab /etc/cron.d/

echo -e "\n[+] User Cron Jobs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "  [!] Cron job found for user: $user"
done

echo -e "\n[+] Scheduled Tasks (Hourly/Daily/Weekly/Monthly):"
ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

echo "--------------------------------------------------"
echo "[+] Audit Complete."
