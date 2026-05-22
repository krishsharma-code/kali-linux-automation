#!/bin/bash

# ip_fetcher.sh
# This script extracts and displays the local IP address of the machine.

echo "Detecting local IP address..."

# 'hostname -I' is a simple way to get IP addresses assigned to the host.
# We use 'awk' to print only the first IP address found.
LOCAL_IP=$(hostname -I | awk '{print $1}')

if [ -n "$LOCAL_IP" ]; then
    echo "Your local IP address is: $LOCAL_IP"
else
    # Fallback method using 'ip addr' if 'hostname -I' returns nothing.
    LOCAL_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    echo "Your local IP address is: $LOCAL_IP"
fi
