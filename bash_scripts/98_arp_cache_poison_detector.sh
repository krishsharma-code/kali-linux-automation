#!/bin/bash
# 98_arp_cache_poison_detector.sh
# Day 12: System and Network Enumeration

# Description:
#   Scans the local ARP table to detect duplicate MAC addresses mapped to 
#   different IP addresses, which is a sign of ARP Spoofing (Cache Poisoning).

# Cybersecurity Principle:
#   ARP Poisoning is a Man-in-the-Middle (MitM) technique. By monitoring
#   the ARP cache, we can detect if an attacker is attempting to intercept
#   local network traffic.

echo "[*] Initializing ARP Cache Poison Detector..."

# Set interval for checking
INTERVAL=10

while true; do
    # Extract IP and MAC addresses from the ARP table
    # Format typically: IP address HWtype HWaddress Flags Mask Iface
    # We use awk to grab IP ($1) and MAC ($3)
    
    DUPLICATES=$(arp -n | awk 'NR>1 {print $3}' | sort | uniq -d)
    
    if [ ! -z "$DUPLICATES" ]; then
        echo "[!!!] WARNING: Potential ARP Spoofing Detected!"
        for MAC in $DUPLICATES; do
            echo "[-] Duplicate MAC Entry: $MAC"
            echo "[-] Associated IPs:"
            arp -n | grep "$MAC" | awk '{print "    - " $1}'
        done
    else
        echo "[+] ARP Cache clean: $(date)"
    fi
    
    sleep $INTERVAL
done
