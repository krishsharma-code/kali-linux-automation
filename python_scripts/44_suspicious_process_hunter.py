import psutil
import os

def hunt_suspicious_processes():
    """
    Scans running processes to find any executing from suspicious directories.
    Target directories: /tmp, /dev/shm, /var/tmp
    """
    suspicious_dirs = ['/tmp', '/dev/shm', '/var/tmp']
    found_suspicious = False

    print("[*] Hunting for Suspicious Processes...")
    print(f"[*] Target Directories: {', '.join(suspicious_dirs)}")
    print("-" * 50)

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe_path = proc.info['exe']
            if exe_path:
                for s_dir in suspicious_dirs:
                    if exe_path.startswith(s_dir):
                        print(f"[!!!] ALERT: Suspicious Process Found!")
                        print(f"      PID: {proc.info['pid']}")
                        print(f"      Name: {proc.info['name']}")
                        print(f"      User: {proc.info['username']}")
                        print(f"      Path: {exe_path}")
                        print("-" * 50)
                        found_suspicious = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not found_suspicious:
        print("[+] No processes found running from suspicious directories.")

if __name__ == "__main__":
    # Note: On Windows, /tmp doesn't exist, so this will usually return nothing.
    # On Kali/Linux, this is a powerful defensive check.
    try:
        hunt_suspicious_processes()
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        print("[TIP] Ensure 'psutil' is installed: pip install psutil")
