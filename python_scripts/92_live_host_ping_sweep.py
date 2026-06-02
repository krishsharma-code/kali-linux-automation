#!/usr/bin/env python3
"""
92_live_host_ping_sweep.py
Day 12: System and Network Enumeration

Description:
    Performs a concurrent ICMP ping sweep across a target subnet to identify live hosts.
    This script uses threading to increase efficiency during reconnaissance.

Cybersecurity Principle:
    Ping sweeps are a foundational reconnaissance technique used to map out active 
    targets in a network. Detecting these sweeps can help identify early stages of 
    an internal network intrusion.
"""

import subprocess
import threading
import ipaddress
import sys
import platform

# Thread lock for clean console output
print_lock = threading.Lock()

def ping_host(ip):
    """
    Pings a single host and reports if it is responsive.
    """
    # Determine the operating system for the correct ping flag
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-W", "1", str(ip)]
    
    try:
        # Suppress output of the ping command
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            with print_lock:
                print(f"[+] Host Live: {ip}")
                
    except Exception as e:
        with print_lock:
            print(f"[-] Error pinging {ip}: {e}")

def sweep_network(network_cidr):
    """
    Iterates through a subnet and spawns threads for each host.
    """
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        print(f"[*] Starting Ping Sweep on {network_cidr}...\n")
        
        threads = []
        for ip in network.hosts():
            t = threading.Thread(target=ping_host, args=(ip,))
            t.start()
            threads.append(t)
            
        # Wait for all threads to complete
        for t in threads:
            t.join()
            
        print("\n[*] Ping Sweep Completed.")

    except ValueError as e:
        print(f"[-] Invalid Network Format: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 92_live_host_ping_sweep.py <NETWORK_CIDR>")
        print("Example: python3 92_live_host_ping_sweep.py 192.168.1.0/24")
        sys.exit(1)

    sweep_network(sys.argv[1])
