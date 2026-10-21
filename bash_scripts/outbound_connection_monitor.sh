#!/bin/bash
# outbound_connection_monitor.sh - Monitors suspicious outbound connections.
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

# Run for a short duration, or a single pass in test mode (AUDIT/CI set).
MAX_ITER=5
if [ -n "${AUDIT:-}" ] || [ "${CI:-}" = "true" ]; then
    MAX_ITER=1
fi

for i in $(seq 1 "$MAX_ITER"); do
    monitor_connections
    if [ "$MAX_ITER" -gt 1 ]; then
        sleep 2
    fi
done

echo "Monitoring cycle complete."
