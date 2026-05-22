#!/bin/bash

# local_net_analyzer.sh
# A script to automate local network information gathering.
# This script identifies IP addresses, routing tables, and listening services.

REPORT_FILE="local_net_report.txt"

# Clear previous report if it exists
echo "--- Local Network Analysis Report ---" > "$REPORT_FILE"
echo "Generated on: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Gathering network information..."

# 1. Display current local IP addresses and network interfaces
# The 'ip addr' command shows all network interfaces and their assigned IP addresses.
echo "[+] Network Interfaces and IP Addresses:" >> "$REPORT_FILE"
ip addr >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

# 2. Show the local routing table
# The 'ip route' command displays how traffic is directed through the network.
echo "[+] Local Routing Table:" >> "$REPORT_FILE"
ip route >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

# 3. List currently listening services
# 'ss -tuln' is a modern way to see TCP (-t) and UDP (-u) listening (-l) ports with numeric (-n) output.
# Alternatively, 'netstat -tuln' can be used if 'ss' is not available.
echo "[+] Listening Services (TCP/UDP):" >> "$REPORT_FILE"
if command -v ss >/dev/null 2>&1; then
    ss -tuln >> "$REPORT_FILE" 2>&1
else
    netstat -tuln >> "$REPORT_FILE" 2>&1
fi
echo "" >> "$REPORT_FILE"

echo "Analysis complete. Report saved to $REPORT_FILE."
echo "View it by running: cat $REPORT_FILE"
