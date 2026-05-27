import socket

def port_scan(target_ip, ports):
    """
    Simple TCP port scanner using sockets.
    """
    print(f"[*] Scanning {target_ip} for open ports...")
    
    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1) # 1 second timeout
        
        # Try to connect to the port
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        s.close()

if __name__ == "__main__":
    target = "127.0.0.1"
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]
    port_scan(target, common_ports)
