#!/bin/bash
# 99_wireless_interface_auditor.sh
# Day 12: System and Network Enumeration

# Description:
#   Identifies wireless interfaces and their current status (Managed/Monitor).
#   Checks for capabilities needed for wireless auditing (injection, etc.).

# Cybersecurity Principle:
#   "Wireless Reconnaissance" requires specialized hardware states. 
#   Ensuring an interface is correctly in "Monitor Mode" is a prerequisite
#   for capturing WPA/WPA2 handshakes or performing deauthentication attacks.

echo "[*] Auditing Wireless Interfaces..."

# 1. Identify interfaces using iwconfig
WLAN_INTERFACES=$(iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print $1}')

if [ -z "$WLAN_INTERFACES" ]; then
    echo "[-] No wireless interfaces detected."
    exit 1
fi

for IFACE in $WLAN_INTERFACES; do
    echo "[+] Found Interface: $IFACE"
    
    # Check current mode
    MODE=$(iwconfig $IFACE | grep "Mode" | awk '{print $4}' | cut -d: -f2)
    echo "    - Current Mode: $MODE"
    
    # Check if airmon-ng sees it
    echo "    - airmon-ng Check:"
    airmon-ng | grep "$IFACE" | awk '{print "      * Driver: " $3 ", Chipset: " $4 " " $5}'
    
    # Recommendation
    if [ "$MODE" == "Managed" ]; then
        echo "    [!] Action: Use 'airmon-ng start $IFACE' to enable Monitor Mode."
    fi
done

echo "[*] Wireless Audit Completed."
