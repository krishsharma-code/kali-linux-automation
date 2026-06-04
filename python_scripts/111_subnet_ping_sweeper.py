import socket
import threading
import subprocess
import os
import argparse

def ping_host(ip, live_hosts):
    """Pings a host to check if it's alive."""
    # Use ping command based on OS
    param = '-n' if os.name == 'nt' else '-c'
    command = ['ping', param, '1', ip]
    
    try:
        # Suppress output
        if subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            print(f"[+] Host {ip} is UP")
            live_hosts.append(ip)
    except Exception:
        pass

def sweep_subnet(base_ip):
    """Sweeps a /24 subnet."""
    print(f"[*] Starting ping sweep on {base_ip}.0/24...")
    threads = []
    live_hosts = []

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=ping_host, args=(ip, live_hosts))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[*] Sweep complete. Found {len(live_hosts)} live hosts.")
    return live_hosts

def main():
    parser = argparse.ArgumentParser(description="Subnet Ping Sweeper")
    parser.add_argument("subnet", help="The base subnet (e.g., 192.168.1)")
    args = parser.parse_args()

    sweep_subnet(args.subnet)

if __name__ == "__main__":
    main()
