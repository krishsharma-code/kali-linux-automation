#!/bin/bash

# 50_system_baseline_snapshot.sh
# Takes a snapshot of installed packages and services for future comparison.
# Part of Day 7: Defensive Monitoring

TIMESTAMP=$(date +%F_%T)
BASELINE_DIR="baselines/$TIMESTAMP"

mkdir -p "$BASELINE_DIR"

echo "[*] Creating System Baseline Snapshot..."
echo "[*] Destination: $BASELINE_DIR"
echo "--------------------------------------------------"

# Snapshot Installed Packages (Debian/Kali specific)
echo "[+] Saving Installed Packages list..."
dpkg --get-selections > "$BASELINE_DIR/installed_packages.txt"

# Snapshot Running Services
echo "[+] Saving Systemd Services state..."
systemctl list-unit-files --type=service > "$BASELINE_DIR/services_status.txt"

# Snapshot Open Ports
echo "[+] Saving Open Ports snapshot..."
ss -lntup > "$BASELINE_DIR/open_ports.txt"

echo "--------------------------------------------------"
echo "[SUCCESS] Baseline snapshot created in $BASELINE_DIR"
echo "[TIP] Run this monthly and use 'diff' to find unauthorized changes."
