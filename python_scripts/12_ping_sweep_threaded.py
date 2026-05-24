#!/usr/bin/env python3
import subprocess
import threading
from queue import Queue

# 12_ping_sweep_threaded.py
# Concept: Using Multi-threading to speed up network reconnaissance

# Thread-safe queue to hold IP addresses
queue = Queue()

def pinger():
    while True:
        # Get an IP from the queue
        ip = queue.get()
        if ip is None:
            break
        
        # Run ping command (1 packet, 1 second timeout)
        # On Windows it's 'ping -n 1', on Linux it's 'ping -c 1'
        # We assume a Linux environment (Kali)
        try:
            res = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                print(f"[+] {ip} is UP")
        except Exception:
            pass
            
        queue.task_done()

def start_sweep(subnet):
    print(f"[*] Starting threaded ping sweep on {subnet}.0/24...")
    
    # Spawn 50 worker threads
    for _ in range(50):
        t = threading.Thread(target=pinger)
        t.daemon = True
        t.start()

    # Add IPs 1-254 to the queue
    for i in range(1, 255):
        queue.put(f"{subnet}.{i}")

    queue.join()
    print("[*] Sweep complete.")

if __name__ == "__main__":
    base_ip = input("Enter first three octets (e.g., 192.168.1): ") or "192.168.1"
    start_sweep(base_ip)
    # Stop the threads
    for _ in range(50):
        queue.put(None)
