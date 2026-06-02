#!/usr/bin/env python3
"""
95_socket_banner_grabber.py
Day 12: System and Network Enumeration

Description:
    Connects to a specific IP and port to retrieve service banners.
    This is used to identify the version of a service running on a port 
    (e.g., SSH, HTTP, FTP).

Cybersecurity Principle:
    Banner grabbing is a critical step in "Vulnerability Assessment". 
    Knowing the exact version of a service allows an attacker to search 
    for known CVEs (Common Vulnerabilities and Exposures) and exploits.
"""

import socket
import sys

def grab_banner(ip, port):
    """
    Attempts to connect to a port and read the first 1024 bytes of data (the banner).
    """
    print(f"[*] Attempting to grab banner from {ip}:{port}...")
    
    try:
        # Create a socket object
        s = socket.socket()
        
        # Set a short timeout
        s.settimeout(2)
        
        # Connect to the target
        s.connect((ip, int(port)))
        
        # Receive the banner
        banner = s.recv(1024)
        
        if banner:
            print(f"[+] Banner received: \n{banner.decode().strip()}")
        else:
            print("[-] Connected, but no banner was returned.")
            
        s.close()

    except socket.timeout:
        print("[-] Connection timed out.")
    except ConnectionRefusedError:
        print("[-] Connection refused (Port might be closed).")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 95_socket_banner_grabber.py <IP> <PORT>")
        print("Example: python3 95_socket_banner_grabber.py 192.168.1.1 22")
        sys.exit(1)

    grab_banner(sys.argv[1], sys.argv[2])
