#!/bin/bash
# 28_backup_critical_configs.sh
# Day 5: Security Auditing & System Defense
# Description: Automates backing up critical system configuration files.

BACKUP_DIR="/tmp/security_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="critical_configs_$TIMESTAMP.tar.gz"

echo "[*] Initializing Critical Configuration Backup..."

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# List of files to backup
FILES_TO_BACKUP="/etc/passwd /etc/group /etc/shadow /etc/ssh/sshd_config /etc/network/interfaces /etc/hosts"

echo "[*] Archiving critical files..."
tar -czf "$BACKUP_DIR/$BACKUP_FILE" $FILES_TO_BACKUP 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] SUCCESS: Backup created at $BACKUP_DIR/$BACKUP_FILE"
    echo "[*] Backup Integrity (SHA256):"
    sha256sum "$BACKUP_DIR/$BACKUP_FILE"
else
    echo "[!] ERROR: Backup failed. Check permissions."
fi
