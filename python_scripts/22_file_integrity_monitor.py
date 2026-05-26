#!/usr/bin/env python3
"""
22_file_integrity_monitor.py
Day 5: Security Auditing & Log Analysis
Description: Monitors critical files for unauthorized modifications using SHA-256.
"""

import hashlib
import os
import json

# List of critical files to monitor
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "./python_scripts/22_file_integrity_monitor.py" # Self-check
]

DB_FILE = "file_hashes.json"

def get_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"

def run_monitor():
    print("[*] Starting File Integrity Monitor (FIM)...")
    
    # Load previous hashes
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            old_hashes = json.load(f)
    else:
        old_hashes = {}

    current_hashes = {}
    changes_detected = False

    for file in CRITICAL_FILES:
        # For demonstration on Windows, we simulate if file doesn't exist
        if not os.path.exists(file):
            # Simulate a hash if the file is a system file not present on Windows
            current_hash = hashlib.sha256(file.encode()).hexdigest() if "/etc" in file else "FILE_NOT_FOUND"
        else:
            current_hash = get_hash(file)
            
        current_hashes[file] = current_hash

        if file in old_hashes:
            if old_hashes[file] != current_hash:
                print(f"[!!!] ALERT: Modification detected in {file}")
                print(f"      Old Hash: {old_hashes[file][:16]}...")
                print(f"      New Hash: {current_hash[:16]}...")
                changes_detected = True
        else:
            print(f"[+] Now monitoring: {file}")

    if not changes_detected:
        print("[+] No unauthorized changes detected in critical files.")

    # Save current hashes for next run
    with open(DB_FILE, 'w') as f:
        json.dump(current_hashes, f, indent=4)

if __name__ == "__main__":
    run_monitor()
