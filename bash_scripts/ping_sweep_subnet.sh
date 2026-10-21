#!/bin/bash
# Day 8: Ping Sweep Subnet
# Author: Senior Cybersecurity Instructor
# Description: Simple ICMP ping sweep to find live hosts in a /24 subnet.

SUBNET=$1 # Expected format: 192.168.1

if [ -z "$SUBNET" ]; then
    echo "Usage: $0 <subnet_prefix (e.g. 192.168.1)>"
    exit 1
fi

echo "[*] Starting Ping Sweep on $SUBNET.0/24..."

for i in {1..254}; do
    ping -c 1 -W 1 "$SUBNET.$i" | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done

wait
echo "[*] Ping Sweep Finished."
