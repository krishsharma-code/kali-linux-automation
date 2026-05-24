#!/usr/bin/env python3

# 14_local_network_mapper.py
# Concept: Logic for mapping devices on a local subnet (Mock implementation)

import random

def get_local_devices():
    """Simulates the discovery of devices on a local network."""
    hostnames = ["Kali-Workstation", "Router-GW", "Printer-HP", "Android-Phone", "Win10-Desktop", "Smart-TV"]
    devices = []
    
    # Generate mock data
    for i in range(1, 10):
        ip = f"192.168.1.{random.randint(2, 254)}"
        hostname = random.choice(hostnames)
        status = "Online" if random.random() > 0.2 else "Offline"
        devices.append({"ip": ip, "name": hostname, "status": status})
        
    return devices

def display_map(devices):
    print(f"{'IP Address':<15} | {'Hostname':<18} | {'Status'}")
    print("-" * 50)
    for dev in devices:
        print(f"{dev['ip']:<15} | {dev['name']:<18} | {dev['status']}")

if __name__ == "__main__":
    print("[*] Scanning local network (Mock Mode)...")
    discovered_devices = get_local_devices()
    display_map(discovered_devices)
    print("\n[+] Mapping complete. 9 devices analyzed.")
