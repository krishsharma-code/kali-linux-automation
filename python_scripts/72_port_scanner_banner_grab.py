import socket
import threading

def grab_banner(ip, port):
    """Grabs the service banner from a given IP and port."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        print(f"[+] {ip}:{port} is OPEN | Banner: {banner}")
        s.close()
    except Exception:
        # Port might be open but not sending a banner immediately
        pass

def scan_port(ip, port):
    """Checks if a port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            grab_banner(ip, port)
        s.close()
    except Exception:
        pass

def start_scan(target_ip, ports):
    """Starts a multi-threaded scan."""
    print(f"[*] Starting scan on {target_ip}...")
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    print("[*] Scan completed.")

if __name__ == "__main__":
    target = "127.0.0.1"
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]
    start_scan(target, common_ports)
