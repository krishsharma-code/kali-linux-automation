#!/bin/bash
# 03_ip_recon.sh
# Extracts the local IP address using 'ip' or 'ifconfig'.

echo "[*] Attempting to extract local IP address..."

# Use 'ip addr' and grep for the 'inet ' pattern (IPv4)
# We exclude the loopback (127.0.0.1) and extract only the IP
ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1

echo "[+] IP Recon complete."
