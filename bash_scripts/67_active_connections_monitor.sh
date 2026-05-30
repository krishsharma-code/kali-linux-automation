#!/bin/bash
# 67_active_connections_monitor.sh - Monitors suspicious outbound connections.
# Day 9: Forensics and Hardening

LOG_FILE="/tmp/suspicious_connections.log"

echo "--- Active Outbound Connection Monitor ---"
echo "Logging results to $LOG_FILE"
echo "Timestamp | Local Address | Remote Address | Process" > "$LOG_FILE"

monitor_connections() {
    # Using 'ss' to find established TCP connections
    # Filtering out common local/loopback traffic
    ss -tpn state established | grep -vE "127.0.0.1|::1" | while read -r line; do
        TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
        echo "$TIMESTAMP | $line" >> "$LOG_FILE"
        echo "[ALERT] New connection: $line"
    done
}

# Run for a short duration or loop indefinitely
for i in {1..5}; do
    monitor_connections
    sleep 2
done

echo "Monitoring cycle complete."
