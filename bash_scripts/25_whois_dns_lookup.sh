#!/bin/bash
# 25_whois_dns_lookup.sh
# Concept: Combines whois, dig, and nslookup for full target info.
# Description: Performs a comprehensive DNS and WHOIS reconnaissance on a target domain.

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1

echo "--- WHOIS INFO ---"
whois "$DOMAIN" | grep -E "Registrar:|Creation Date:|Registry Expiry Date:|Name Server:"
echo ""

echo "--- DNS A RECORDS ---"
dig +short "$DOMAIN"
echo ""

echo "--- DNS MX RECORDS ---"
dig +short MX "$DOMAIN"
echo ""

echo "--- NSLOOKUP ---"
nslookup "$DOMAIN"
