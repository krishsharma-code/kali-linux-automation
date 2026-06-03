import subprocess

def audit_systemd_services():
    """
    Evaluates active systemd services, tracking metadata traces 
    to find non-standard startup configs.
    """
    print("=== Systemd Service Auditor ===")
    print("[*] Listing active services and checking for non-standard paths...")
    
    try:
        # Get active services
        result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend'], 
                               capture_output=True, text=True)
        lines = result.stdout.splitlines()
    except Exception as e:
        print(f"[!] Error running systemctl: {e}")
        return

    non_standard = 0
    for line in lines:
        service_name = line.split()[0]
        
        # Check service fragment path
        try:
            show_result = subprocess.run(['systemctl', 'show', service_name, '--property=FragmentPath'], 
                                        capture_output=True, text=True)
            path = show_result.stdout.strip().split('=')[-1]
            
            # Standard paths are usually /lib/systemd/system/ or /etc/systemd/system/
            if not any(path.startswith(p) for p in ['/lib/systemd/system', '/usr/lib/systemd/system', '/etc/systemd/system']):
                if path: # Ensure path isn't empty
                    print(f"[!] NON-STANDARD PATH: {service_name} -> {path}")
                    non_standard += 1
            
            # Check for services running from /tmp or /home
            if any(p in path for p in ['/tmp', '/home', '/var/tmp']):
                print(f"    [!] HIGH RISK: Service {service_name} is running from {path}")

        except Exception:
            continue

    if non_standard == 0:
        print("[+] All active systemd services are running from standard locations.")
    else:
        print(f"[*] Audit complete. {non_standard} non-standard services found.")

if __name__ == "__main__":
    audit_systemd_services()
