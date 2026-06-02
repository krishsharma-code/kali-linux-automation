#!/bin/bash
# 100_network_recon_bundle.sh
# Day 12: System and Network Enumeration

# Description:
#   A comprehensive reconnaissance automation script that aggregates 
#   network configuration, routing, and DNS data into a forensic report.

# Cybersecurity Principle:
#   "Information Gathering" is the first phase of any penetration test.
#   Automating this process ensures consistency and speed, allowing the
#   auditor to focus on analyzing the data rather than collecting it.

REPORT_FILE="network_recon_dump_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] Starting Comprehensive Network Reconnaissance..."
echo "[*] Saving output to $REPORT_FILE"

{
    echo "=========================================="
    echo " NETWORK RECONNAISSANCE FORENSIC DUMP "
    echo " Date: $(date)"
    echo " User: $(whoami)"
    echo "=========================================="

    echo -e "\n[+] 1. Interface Configurations (ip a):"
    ip a

    echo -e "\n[+] 2. Routing Table (route -n):"
    route -n

    echo -e "\n[+] 3. DNS Nameservers (resolv.conf):"
    cat /etc/resolv.conf | grep "nameserver"

    echo -e "\n[+] 4. Active Listening Ports (ss -lntu):"
    ss -lntu

    echo -e "\n[+] 5. Local Subnet Live Hosts (ARP Table):"
    arp -n

    echo -e "\n[+] 6. External IP Resolution:"
    curl -s https://ifconfig.me && echo ""

    echo "=========================================="
    echo "           END OF REPORT                "
    echo "=========================================="
} > "$REPORT_FILE"

echo "[+] Reconnaissance Complete. Report saved to $REPORT_FILE"
