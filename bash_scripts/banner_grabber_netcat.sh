#!/bin/bash
# Day 8: Banner Grabber (Netcat)
# Author: Senior Cybersecurity Instructor
# Description: Uses netcat to grab service banners from a target port.

TARGET=$1
PORT=$2

if [ -z "$TARGET" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <target> <port>"
    exit 1
fi

echo "[*] Attempting banner grab on $TARGET:$PORT..."

# Send an empty string and wait 2 seconds for a response
echo "" | nc -vn -w 2 "$TARGET" "$PORT" 2>&1 | grep -v "refused"

if [ $? -ne 0 ]; then
    echo "[-] No banner received or connection failed."
fi
