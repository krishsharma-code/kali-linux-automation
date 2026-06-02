#!/bin/bash
# 96_active_connections_monitor.sh
# Day 12: System and Network Enumeration

# Description:
#   Continuously monitors established network connections and alerts
#   when a new connection is established.

# Cybersecurity Principle:
#   "Continuous Monitoring" is essential for detecting unauthorized data
#   exfiltration or command-and-control (C2) callbacks. By baselining
#   normal connections, we can quickly spot anomalies.

echo "[*] Initializing Active Connection Monitor..."
echo "[*] Monitoring established TCP connections..."

# Store initial state of established connections
INITIAL_CONNECTIONS=$(ss -antp | grep "ESTAB" | awk '{print $5}' | sort | uniq)

while true; do
    # Get current established connections
    CURRENT_CONNECTIONS=$(ss -antp | grep "ESTAB" | awk '{print $5}' | sort | uniq)
    
    # Check for new connections not in the initial list
    for CONN in $CURRENT_CONNECTIONS; do
        if ! echo "$INITIAL_CONNECTIONS" | grep -q "$CONN"; then
            echo "[!] ALERT: New Established Connection Detected: $CONN"
            # Update initial list to include the new connection (or keep alerting)
            # For this script, we'll just alert and add to baseline for now
            INITIAL_CONNECTIONS=$(echo -e "$INITIAL_CONNECTIONS\n$CONN" | sort | uniq)
        fi
    done
    
    sleep 5
done
