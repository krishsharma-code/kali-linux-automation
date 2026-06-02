#!/usr/bin/env python3
"""
93_mac_address_spoof_automator.py
Day 12: System and Network Enumeration

Description:
    Automates the process of changing a network interface's MAC address on Linux systems.
    It takes the interface down, rotates the MAC address, and brings it back up.

Cybersecurity Principle:
    MAC spoofing is used to maintain anonymity on a local network or to bypass 
    MAC-based filtering/access control lists (ACLs). It is a common technique 
    used in red-teaming to blend in with authorized devices.
"""

import subprocess
import sys
import random
import re

def get_random_mac():
    """
    Generates a random valid MAC address.
    """
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def change_mac(interface, new_mac):
    """
    Configures the network interface with a new MAC address.
    """
    print(f"[*] Switching {interface} to new MAC: {new_mac}")
    
    try:
        # 1. Bring interface down
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        
        # 2. Change MAC
        subprocess.run(["ip", "link", "set", interface, "address", new_mac], check=True)
        
        # 3. Bring interface up
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        
        print(f"[+] Successfully changed MAC on {interface}")
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: Failed to change MAC address. Ensure you have root privileges: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 93_mac_address_spoof_automator.py <INTERFACE> [NEW_MAC]")
        print("Example: python3 93_mac_address_spoof_automator.py eth0")
        sys.exit(1)

    iface = sys.argv[1]
    
    # If no MAC provided, generate a random one
    new_mac = sys.argv[2] if len(sys.argv) > 2 else get_random_mac()
    
    # Validate MAC format
    if not re.match(r"[0-9a-f]{2}([:][0-9a-f]{2}){5}", new_mac.lower()):
        print("[-] Error: Invalid MAC address format.")
        sys.exit(1)

    change_mac(iface, new_mac)
