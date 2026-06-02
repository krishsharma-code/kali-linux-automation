#!/usr/bin/env python3
"""
91_subnet_mask_parser.py
Day 12: System and Network Enumeration

Description:
    A technical utility to parse CIDR notation and calculate network parameters.
    This script provides the network ID, broadcast address, valid host range, 
    and total host capacity, which are critical for network segmentation auditing.

Cybersecurity Principle:
    Understanding network boundaries is the first step in "Least Privilege" network 
    design and is essential for identifying unauthorized subnets during enumeration.
"""

import ipaddress
import sys

def parse_subnet(cidr):
    """
    Parses CIDR notation and prints detailed network statistics.
    """
    try:
        # Create an IPv4 network object
        network = ipaddress.IPv4Network(cidr, strict=False)
        
        print(f"\n[+] Network Analysis for: {cidr}")
        print("-" * 40)
        print(f"Network ID:        {network.network_address}")
        print(f"Subnet Mask:       {network.netmask}")
        print(f"Broadcast Address: {network.broadcast_address}")
        print(f"Wildcard Mask:     {network.hostmask}")
        print(f"First Host:        {list(network.hosts())[0] if network.num_addresses > 2 else 'N/A'}")
        print(f"Last Host:         {list(network.hosts())[-1] if network.num_addresses > 2 else 'N/A'}")
        print(f"Total Hosts:       {network.num_addresses}")
        print(f"Valid Host Count:  {max(0, network.num_addresses - 2)}")
        print("-" * 40)

    except ValueError as e:
        print(f"[-] Error: Invalid CIDR notation: {e}")
    except IndexError:
        print("[-] Error: Subnet too small for host calculations.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 91_subnet_mask_parser.py <CIDR_NOTATION>")
        print("Example: python3 91_subnet_mask_parser.py 192.168.1.0/24")
        sys.exit(1)

    parse_subnet(sys.argv[1])
