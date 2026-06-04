import os
import sys
import subprocess
import platform

def is_termux():
    """Checks if the script is running inside Termux."""
    return 'TERMUX_VERSION' in os.environ or os.path.exists('/data/data/com.termux')

def audit_termux():
    """Audits Termux-specific permissions and environment."""
    print("=== Termux Environment Mapper ===")
    
    if not is_termux():
        print("[!] Not running in Termux. Skipping Termux-specific checks.")
        return

    print("[+] Termux Detected!")
    print(f"[*] Termux Version: {os.environ.get('TERMUX_VERSION', 'Unknown')}")
    
    # Check for root
    is_root = os.getuid() == 0
    print(f"[*] Root Status: {'Rooted' if is_root else 'Not Root'}")

    # Check for storage permission
    storage_path = os.path.join(os.environ.get('HOME', ''), 'storage')
    if os.path.exists(storage_path):
        print("[+] Storage Permission: GRANTED")
    else:
        print("[-] Storage Permission: NOT GRANTED (Run 'termux-setup-storage')")

    # Check for Termux-API
    try:
        res = subprocess.run(['termux-battery-status'], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Termux-API: INSTALLED")
            print(f"[*] Battery Info: {res.stdout.strip()}")
        else:
            print("[-] Termux-API: NOT INSTALLED or NOT RESPONDING")
    except FileNotFoundError:
        print("[-] Termux-API: NOT INSTALLED")

    # Audit installed packages (mini)
    print("\n[*] Auditing Common Tools:")
    tools = ['nmap', 'python', 'git', 'metasploit', 'tsu']
    for tool in tools:
        found = subprocess.run(['which', tool], capture_output=True).returncode == 0
        print(f"    - {tool}: {'[INSTALLED]' if found else '[NOT FOUND]'}")

def main():
    audit_termux()

if __name__ == "__main__":
    main()
