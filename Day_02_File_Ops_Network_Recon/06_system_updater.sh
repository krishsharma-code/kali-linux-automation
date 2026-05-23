#!/bin/bash
# 06_system_updater.sh
# A wrapper script to update and upgrade the Linux system.

echo "[*] Starting system update..."

# 'sudo apt update' refreshes the package lists
# 'sudo apt upgrade -y' upgrades all packages without asking for confirmation (-y)
# '&&' ensures upgrade only runs if update is successful
sudo apt update && sudo apt upgrade -y

echo "[+] System update and upgrade complete."
