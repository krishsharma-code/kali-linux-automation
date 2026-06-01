#!/usr/bin/env python3
"""
83_log_file_monitor.py
Day 11: Local Enumeration
Description: A script that tails a mock auth.log file and alerts on failed SSH logins.
"""

import time
import os

def monitor_auth_log():
    # In a real scenario, this would be /var/log/auth.log
    log_file = "mock_auth.log"
    
    # Create a mock file if it doesn't exist for demonstration
    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write("Jun 01 10:00:01 kali sshd[1234]: Accepted password for root from 192.168.1.1\n")

    print(f"[*] Monitoring {log_file} for failed SSH attempts (Type Ctrl+C to stop)...")
    
    try:
        with open(log_file, "r") as f:
            # Go to the end of the file
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Wait for new data
                    continue
                
                if "Failed password" in line or "Authentication failure" in line:
                    print(f"[!!!] ALERT: {line.strip()}")
                elif "Accepted password" in line:
                    print(f"[+] Login Detected: {line.strip()}")
                    
    except KeyboardInterrupt:
        print("\n[*] Stopping log monitor...")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    monitor_auth_log()
