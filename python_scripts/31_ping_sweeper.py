import subprocess
import os

def ping_sweep(network_prefix):
    """
    Pings a /24 subnet to find live hosts.
    Example network_prefix: '192.168.1'
    """
    print(f"[*] Starting ping sweep on {network_prefix}.0/24...")
    live_hosts = []
    
    # Loop through 1 to 254
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        # -c 1 (1 packet), -W 1 (1 second timeout)
        response = subprocess.run(["ping", "-c", "1", "-W", "1", ip], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL)
        
        if response.returncode == 0:
            print(f"[+] Host {ip} is UP")
            live_hosts.append(ip)
            
    return live_hosts

if __name__ == "__main__":
    # Example target (adjust as needed for local testing)
    target_net = "127.0.0" 
    ping_sweep(target_net)
