#!/bin/bash

# Kernel Parameter Tuner
# Modifies system memory parameters to prevent routing spoof injection over network vectors.

echo "=== Kernel Parameter Tuner ==="

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root." 
   exit 1
fi

# Hardening IPv4 networking
echo "[*] Hardening network stack (IPv4)..."

# Ignore ICMP broadcasts
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

# Ignore bogus ICMP errors
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# Do not accept IP source route packets
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# Disable ICMP redirect acceptance
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# Enable IP spoofing protection (Reverse Path Filtering)
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Log Martians (packets with impossible source addresses)
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# Reload sysctl settings from config file
sysctl -p

echo "[+] Kernel network parameters have been hardened."
