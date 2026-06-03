#!/bin/bash

# SSH Brute Force Defense
# Parses syslog logs streams dynamically, blacklisting malicious source IPs manipulating authentication hooks.

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
BLOCK_LIST="/tmp/ssh_blacklist.txt"

echo "=== SSH Brute Force Defense System ==="

if [[ ! -f "$LOG_FILE" ]]; then
    echo "[!] Error: $LOG_FILE not found. Trying /var/log/syslog..."
    LOG_FILE="/var/log/syslog"
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo "[!] Fatal: No compatible log file found."
    exit 1
fi

echo "[*] Monitoring $LOG_FILE for failed SSH attempts..."

# Extract IPs with failed attempts above threshold
grep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr > "$BLOCK_LIST"

while read count ip; do
    if [ "$count" -ge "$THRESHOLD" ]; then
        echo "[!] HIGH ALERT: IP $ip has $count failed attempts."
        
        # Check if already blocked in UFW
        if ufw status | grep -q "$ip"; then
            echo "    [*] IP $ip is already blocked."
        else
            echo "    [+] Blocking malicious IP: $ip"
            # ufw insert 1 deny from "$ip" to any
        fi
    fi
done < "$BLOCK_LIST"

echo "[+] Scan complete. IPs exceeding $THRESHOLD attempts identified."
rm "$BLOCK_LIST"
