#!/bin/bash

# open_ports.sh
# This script lists currently listening network ports.

echo "--- Active Listening Ports ---"

# Check if 'ss' (Socket Statistics) is available.
if command -v ss >/dev/null 2>&1; then
    # '-t' TCP, '-u' UDP, '-l' listening, '-n' numeric.
    echo "Using 'ss' command:"
    ss -tuln
else
    # Fallback to 'netstat' if 'ss' is missing.
    echo "Using 'netstat' command:"
    netstat -tuln
fi

echo "------------------------------"
