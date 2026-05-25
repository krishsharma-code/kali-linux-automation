#!/bin/bash
# 24_wget_mirror.sh
# Concept: Script to download and mirror a basic website.
# Description: Uses wget to mirror a target site locally for offline analysis.

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

URL=$1
DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')

echo "[*] Mirroring $URL to local folder: $DOMAIN"

wget --mirror --convert-links --adjust-extension --page-requisites --no-parent "$URL" -P "./mirrors/$DOMAIN"

echo "[+] Mirroring complete. Check ./mirrors/$DOMAIN"
