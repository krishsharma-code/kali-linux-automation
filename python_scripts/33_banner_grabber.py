import socket

def grab_banner(ip, port):
    """
    Connects to a port and attempts to read the service banner.
    """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        
        # Some services require a trigger to send a banner
        # For a basic grab, we just try to receive
        banner = s.recv(1024).decode().strip()
        return banner
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        s.close()

if __name__ == "__main__":
    target_ip = "127.0.0.1"
    target_port = 80 # Example port
    print(f"[*] Attempting banner grab on {target_ip}:{target_port}")
    banner = grab_banner(target_ip, target_port)
    if banner:
        print(f"[+] Service Banner: {banner}")
    else:
        print("[-] No banner received.")
