#!/usr/bin/env python3
"""
81_passwd_file_analyzer.py
Day 11: Local Enumeration
Description: Reads /etc/passwd and extracts users with interactive shell access.
"""

import os

def analyze_passwd():
    passwd_path = "/etc/passwd"
    
    # Check if the file exists (to avoid errors in non-Linux environments)
    if not os.path.exists(passwd_path):
        print(f"[-] Error: {passwd_path} not found. Are you on a Linux system?")
        return

    interactive_shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh"]
    
    print(f"[*] Analyzing {passwd_path} for interactive users...")
    print("-" * 50)
    print(f"{'Username':<15} {'UID':<6} {'Shell':<15}")
    print("-" * 50)

    try:
        with open(passwd_path, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    username = parts[0]
                    uid = parts[2]
                    shell = parts[6]
                    
                    if shell in interactive_shells:
                        print(f"{username:<15} {uid:<6} {shell:<15}")
                        
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    analyze_passwd()
