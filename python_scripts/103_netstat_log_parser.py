import subprocess
import re

def parse_netstat():
    """
    Parses network connections and outputs alerts if unprivileged ports
    bind to outside addresses.
    """
    print("=== Netstat Logic Parser ===")
    print("[*] Analyzing active network connections...")
    
    try:
        # Running 'ss' as it is the modern replacement for netstat
        result = subprocess.run(['ss', '-tunpl'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
    except FileNotFoundError:
        print("[!] Error: 'ss' command not found. Install iproute2.")
        return

    alerts = 0
    # Headers start at line 0, data starts at line 1
    for line in lines[1:]:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 5: continue
        
        local_addr = parts[4] # e.g., 0.0.0.0:22 or [::]:22
        
        # Extract port
        port_match = re.search(r':(\d+)$', local_addr)
        if port_match:
            port = int(port_match.group(1))
            
            # Unprivileged ports are > 1024
            if port > 1024:
                # Basic check for listening on all interfaces (0.0.0.0 or *)
                if local_addr.startswith('0.0.0.0') or local_addr.startswith('*') or local_addr.startswith('[::]'):
                    print(f"[!] ALERT: Unprivileged port {port} is binding to ALL interfaces!")
                    print(f"    Line: {line}")
                    alerts += 1

    if alerts == 0:
        print("[+] No suspicious unprivileged port bindings found.")
    else:
        print(f"[*] Analysis complete. {alerts} alerts triggered.")

if __name__ == "__main__":
    parse_netstat()
