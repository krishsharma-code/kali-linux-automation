#!/bin/bash
# 02_network_ping.sh
# Checks network connectivity by pinging a host 3 times.

TARGET="google.com"

echo "[*] Checking connectivity to $TARGET..."

# 'ping -c 3' sends exactly 3 packets
# This is used to verify if the host is alive and reachable
ping -c 3 $TARGET

echo "[+] Ping test completed."
