#!/bin/bash

# 19_route_tracer.sh
# Concept: Automating traceroute for path discovery

TARGET=$1

if [ -z "$TARGET" ]; then
    TARGET="8.8.8.8"
fi

echo "[*] Tracing route to $TARGET..."
echo "--------------------------------"

# -n: numeric output (faster, no DNS resolution)
traceroute -n "$TARGET" 2>/dev/null || echo "[!] traceroute failed. Is it installed?"

echo "--------------------------------"
echo "[+] Trace complete."
