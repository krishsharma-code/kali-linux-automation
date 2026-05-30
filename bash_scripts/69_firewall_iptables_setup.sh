#!/bin/bash
# 69_firewall_iptables_setup.sh - Basic defensive firewall configuration.
# Day 9: Forensics and Hardening

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." 
   exit 1
fi

echo "--- Hardening Network with IPTables ---"

# Flush existing rules
iptables -F

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related inbound connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (Port 22) - Optional/Restrictive
# iptables -A INPUT -p tcp --dport 22 -j ACCEPT

echo "[OK] Firewall rules applied."
echo "Default Policy: DROP Inbound | ACCEPT Outbound"
iptables -L -n
