#!/bin/bash
# 68_file_integrity_monitor.sh - Checks hashes of critical system files.
# Day 9: Forensics and Hardening

HASH_DB="/tmp/sys_file_hashes.db"
CRITICAL_FILES=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/usr/bin/ssh")

generate_hashes() {
    echo "Initializing Hash Database..."
    for file in "${CRITICAL_FILES[@]}"; do
        if [ -f "$file" ]; then
            sha256sum "$file" >> "$HASH_DB"
        fi
    done
}

verify_integrity() {
    echo "Starting Integrity Verification..."
    if [ ! -f "$HASH_DB" ]; then
        generate_hashes
        return
    fi

    sha256sum -c "$HASH_DB" --status
    if [ $? -eq 0 ]; then
        echo "[OK] All critical files are intact."
    else
        echo "[ALERT] Integrity Violation Detected! Check /var/log/syslog."
        sha256sum -c "$HASH_DB" | grep "FAILED"
    fi
}

verify_integrity
