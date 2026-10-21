#!/bin/bash
# SAFE_HELP_GUARD: non-destructive --help (exits before any state change).
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: $(basename "$0") [options]"
    echo "This is a state-changing tool. --help makes no changes and exits."
    exit 0
fi

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root" 
   exit 1
fi

echo "[*] Flushing existing iptables rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo "[*] Setting default policies to DROP..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo "[*] Allowing established and related connections..."
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[*] Allowing loopback interface..."
iptables -A INPUT -i lo -j ACCEPT

echo "[*] Allowing SSH (port 22)..."
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

echo "[*] Allowing HTTP (port 80) and HTTPS (port 443)..."
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

echo "[+] Security configuration complete."
iptables -L -v
