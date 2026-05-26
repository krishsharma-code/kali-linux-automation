#!/usr/bin/env python3
"""
23_active_ports_analyzer.py
Day 5: Security Auditing & Log Analysis
Description: Lists local listening ports and associated processes.
"""

import socket
import psutil

def analyze_ports():
    print("[*] Auditing Local Listening Ports...")
    print("-" * 60)
    print(f"{'Protocol':<10} {'Local Address':<20} {'Port':<10} {'PID':<10} {'Process Name'}")
    print("-" * 60)

    # Get all network connections
    connections = psutil.net_connections(kind='inet')
    
    listening_found = False
    for conn in connections:
        if conn.status == 'LISTEN':
            listening_found = True
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            laddr = f"{conn.laddr.ip}"
            port = conn.laddr.port
            pid = conn.pid
            
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown/Access Denied"

            print(f"{protocol:<10} {laddr:<20} {port:<10} {pid:<10} {process_name}")

    if not listening_found:
        print("[!] No active listening ports found (check permissions).")

if __name__ == "__main__":
    analyze_ports()
