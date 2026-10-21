#!/bin/bash

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root" 
   exit 1
fi

echo "=== Kali Workstation Maintenance ==="
echo "[*] Updating package lists..."
apt-get update

echo "[*] Upgrading system packages (safe upgrade)..."
apt-get upgrade -y

echo "[*] Removing unnecessary dependencies..."
apt-get autoremove -y

echo "[*] Cleaning local repository of retrieved package files..."
apt-get clean
apt-get autoclean

echo "[*] Checking for broken dependencies..."
apt-get check

echo "[+] Maintenance complete. System is lean and updated."
