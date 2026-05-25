#!/bin/bash
# 21_curl_header_grabber.sh
# Concept: Fast curl command to inspect headers.
# Description: Uses curl to fetch only the HTTP headers of a target.

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

URL=$1

echo "[*] Grabbing headers for: $URL"
echo "-----------------------------------"
curl -I -s -L "$URL"
echo "-----------------------------------"
