#!/bin/bash

# Auditd Report Aggregator
# Packages core kernel logs, environment changes, and login logs into a locked, read-only forensics report bundle.

REPORT_DIR="/tmp/security_report_$(date +%F_%H%M)"
REPORT_FILE="/root/final_security_bundle.tar.gz"

echo "=== Auditd Report Aggregator ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root." 
   exit 1
fi

mkdir -p "$REPORT_DIR"

echo "[*] Collecting system logs..."
cp /var/log/auth.log "$REPORT_DIR/" 2>/dev/null
cp /var/log/syslog "$REPORT_DIR/" 2>/dev/null
cp /var/log/audit/audit.log "$REPORT_DIR/" 2>/dev/null

echo "[*] Gathering environment state..."
env > "$REPORT_DIR/environment_vars.txt"
who > "$REPORT_DIR/logged_in_users.txt"
last > "$REPORT_DIR/login_history.txt"
ps aux > "$REPORT_DIR/process_snapshot.txt"

echo "[*] Compressing report bundle..."
tar -czf "$REPORT_FILE" -C "$REPORT_DIR" .

echo "[*] Locking report file (read-only)..."
chmod 400 "$REPORT_FILE"
chattr +i "$REPORT_FILE" 2>/dev/null # Attempt to make immutable

echo "[+] Report bundle created at: $REPORT_FILE"
echo "[*] Cleanup of temporary files..."
rm -rf "$REPORT_DIR"

echo "=== Aggregator Complete ==="
