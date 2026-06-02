#!/bin/bash
# 97_iptables_firewall_reset.sh
# Day 12: System and Network Enumeration

# Description:
#   Backs up current iptables, flushes all rules, sets default policy to DROP,
#   and opens specific whitelist ports (SSH, HTTP, HTTPS).

# Cybersecurity Principle:
#   "Default Deny" is a core security posture. By blocking all traffic by default 
#   and only allowing explicit authorized services, we drastically reduce the 
#   attack surface of the host.

echo "[*] Resetting iptables Firewall to Secure State..."

# 1. Backup existing rules
iptables-save > firewall_backup_$(date +%F).txt
echo "[+] Current rules backed up."

# 2. Flush all existing rules and chains
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# 3. Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 4. Allow Loopback (Localhost)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 5. Allow established and related incoming traffic
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 6. Whitelist Services
# Allow SSH (Port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
echo "[+] SSH (22) whitelisted."

# Allow HTTP/HTTPS (80/443)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
echo "[+] Web Traffic (80, 443) whitelisted."

# 7. List current rules
echo "[*] Firewall Configuration Updated:"
iptables -L -n -v
