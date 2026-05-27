#!/bin/bash

# ARP Discovery Script
# Identifies local devices using ARP requests

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo)."
  exit 1
fi

# Detect local interface and subnet automatically if possible
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
SUBNET=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}')

echo "[*] Starting ARP discovery on $INTERFACE ($SUBNET)..."

# Using Nmap's ARP ping for discovery
nmap -sn -PR $SUBNET
