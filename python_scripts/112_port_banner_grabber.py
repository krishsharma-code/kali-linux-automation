import socket
import argparse
import sys

def get_banner(ip, port):
    """Attempts to grab the banner from a specific port."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        
        # Some services require a trigger to send a banner
        # We'll just try to receive first
        banner = s.recv(1024).decode().strip()
        if banner:
            return banner
        
        # If no banner, try sending a generic request (e.g., for HTTP)
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        return banner
    except Exception:
        return None
    finally:
        s.close()

def main():
    parser = argparse.ArgumentParser(description="Port Banner Grabber")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--ports", help="Comma-separated list of ports", default="21,22,25,80,443,3306,8080")
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    print(f"[*] Starting banner grabbing on {args.target}...")

    for port in ports:
        banner = get_banner(args.target, port)
        if banner:
            print(f"[+] Port {port}: {banner}")
        else:
            # Check if port is open but no banner
            try:
                s = socket.socket()
                s.settimeout(1)
                res = s.connect_ex((args.target, port))
                if res == 0:
                    print(f"[?] Port {port}: Open (No banner)")
                s.close()
            except:
                pass

if __name__ == "__main__":
    main()
