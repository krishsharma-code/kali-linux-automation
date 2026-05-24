#!/bin/bash

# 20_arp_table_reader.sh
# Concept: Reading and formatting the local ARP cache

echo "[*] Current ARP Cache (Address Resolution Protocol):"
echo "----------------------------------------------------"

# On Linux, 'arp -n' or 'ip neigh' shows the table
# We use 'arp -n' for a classic view
arp -n 2>/dev/null | column -t || echo "[!] ARP command not found. Try 'ip neigh'."

echo "----------------------------------------------------"
echo "[+] ARP table dump finished."
