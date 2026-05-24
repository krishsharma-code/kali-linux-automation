#!/usr/bin/env python3
import socket

# 11_socket_banner_grabber.py
# Concept: Low-level socket programming for service identification (Banner Grabbing)

def grab_banner(ip, port):
    try:
        # Create a socket object
        s = socket.socket()
        # Set a timeout so we don't wait forever
        s.settimeout(2)
        # Connect to the target
        s.connect((ip, port))
        # Receive up to 1024 bytes
        banner = s.recv(1024).decode().strip()
        return banner
    except Exception as e:
        return f"Could not connect or no banner: {e}"
    finally:
        s.close()

if __name__ == "__main__":
    target = input("Enter Target IP: ") or "127.0.0.1"
    port = int(input("Enter Port (e.g., 22, 80): ") or "22")
    
    print(f"[*] Attempting to grab banner from {target}:{port}...")
    banner = grab_banner(target, port)
    print(f"[+] Service Banner: {banner}")
