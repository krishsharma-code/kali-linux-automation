#!/bin/bash

OUTPUT_FILE="cronjob_audit_$(date +%F).txt"

echo "=== Cronjob Security Audit - $(date) ===" > "$OUTPUT_FILE"
echo "Host: $(hostname)" >> "$OUTPUT_FILE"
echo "----------------------------------------" >> "$OUTPUT_FILE"

echo "[*] Auditing System-wide Cronjobs..."
echo "\n--- System Cron (/etc/crontab) ---" >> "$OUTPUT_FILE"
cat /etc/crontab >> "$OUTPUT_FILE"

echo "\n--- Cron Directories (/etc/cron.*) ---" >> "$OUTPUT_FILE"
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly >> "$OUTPUT_FILE"

echo "[*] Auditing User Cronjobs..."
echo "\n--- User Crontabs ---" >> "$OUTPUT_FILE"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null > /tmp/user_cron
    if [ -s /tmp/user_cron ]; then
        echo "User: $user" >> "$OUTPUT_FILE"
        cat /tmp/user_cron >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
done
rm /tmp/user_cron

echo "[*] Checking for recently modified entries (24h)..."
echo "\n--- Recently Modified Files in /etc/cron.* ---" >> "$OUTPUT_FILE"
find /etc/cron* -mtime -1 -ls >> "$OUTPUT_FILE"

echo "[+] Audit complete. Report saved to: $OUTPUT_FILE"
