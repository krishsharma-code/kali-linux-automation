#!/bin/bash
# Day 8: WHOIS IP Lookup
# Author: Senior Cybersecurity Instructor
# Description: Performs WHOIS lookups on a list of IPs.

IP_LIST=$1

if [ -z "$IP_LIST" ]; then
    echo "Usage: $0 <ip_list_file_or_single_ip>"
    exit 1
fi

lookup_ip() {
    local ip=$1
    echo "-----------------------------------"
    echo "[*] WHOIS Lookup for: $ip"
    whois "$ip" | grep -Ei "OrgName|NetName|Country|Organization" | sort -u
}

if [ -f "$IP_LIST" ]; then
    while IFS= read -r line; do
        lookup_ip "$line"
    done < "$IP_LIST"
else
    lookup_ip "$IP_LIST"
fi
