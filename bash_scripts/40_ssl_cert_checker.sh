#!/bin/bash

# SSL Certificate Checker
# Checks expiration and details of an SSL cert

if [ -z "$1" ]; then
    echo "Usage: $0 <hostname>"
    exit 1
fi

TARGET=$1
PORT=${2:-443}

echo "[*] Checking SSL certificate for $TARGET on port $PORT..."

echo | openssl s_client -connect "$TARGET:$PORT" 2>/dev/null | openssl x509 -noout -dates -issuer -subject
