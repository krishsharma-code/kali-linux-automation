import os
import sys

def hunt_anomalies():
    """
    Inspects running processes via /proc, looks for unlinked binaries,
    and highlights potential execution indicators of malware.
    """
    print("=== Process Anomaly Hunter ===")
    print("[*] Scanning /proc for unlinked binaries (deleted but running)...")
    
    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"[!] Error accessing /proc: {e}")
        return

    anomalies_found = 0
    for pid in pids:
        try:
            exe_path = os.readlink(f'/proc/{pid}/exe')
            if '(deleted)' in exe_path:
                print(f"[!] ANOMALY DETECTED: PID {pid} is running from a deleted binary: {exe_path}")
                anomalies_found += 1
                
                # Check for suspicious paths
                if any(path in exe_path for path in ['/tmp', '/dev/shm', '/var/tmp']):
                    print(f"    [!] WARNING: PID {pid} is executing from a highly suspicious path!")

        except (OSError, PermissionError):
            # Process might have ended or we don't have permission
            continue

    if anomalies_found == 0:
        print("[+] No unlinked process anomalies detected.")
    else:
        print(f"[*] Scan complete. {anomalies_found} anomalies highlighted.")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[!] This script should be run as root for full visibility.")
    hunt_anomalies()
