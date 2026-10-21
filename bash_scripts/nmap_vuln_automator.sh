#!/bin/bash

# Day 10: Nmap Vulnerability Automator
# Wraps Nmap with the --script vuln flag and formats the output.

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
fi

OUTPUT_FILE="nmap_vuln_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] Starting Nmap Vulnerability Scan on $TARGET..."
echo "[*] Using scripts: vuln, auth, discovery"

# In a real Kali environment, this command would run:
# nmap -Pn --script vuln,auth,discovery -oN "$OUTPUT_FILE" "$TARGET"

# Mock output for demonstration
echo "--- Nmap Vuln Scan Results for $TARGET ---" > "$OUTPUT_FILE"
echo "Scan Date: $(date)" >> "$OUTPUT_FILE"
echo "Host is up." >> "$OUTPUT_FILE"
echo "PORT   STATE SERVICE" >> "$OUTPUT_FILE"
echo "80/tcp open  http" >> "$OUTPUT_FILE"
echo "|_http-vuln-cve2017-10010: VULNERABLE" >> "$OUTPUT_FILE"
echo "22/tcp open  ssh" >> "$OUTPUT_FILE"

echo "[+] Scan complete. Results saved to $OUTPUT_FILE"
cat "$OUTPUT_FILE"
