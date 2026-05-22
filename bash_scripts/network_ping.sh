#!/bin/bash

# network_ping.sh
# This script pings a specified domain 3 times to check network connectivity.

# Check if a domain argument was provided.
# $1 represents the first argument passed to the script.
if [ -z "$1" ]; then
    echo "Usage: ./network_ping.sh <domain_or_ip>"
    echo "Example: ./network_ping.sh google.com"
    exit 1
fi

DOMAIN=$1

echo "Checking connectivity to $DOMAIN..."

# 'ping -c 3' sends 3 packets to the target domain.
ping -c 3 "$DOMAIN"

echo "Ping attempt finished."
