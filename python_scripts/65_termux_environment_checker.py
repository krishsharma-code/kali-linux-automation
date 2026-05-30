#!/usr/bin/env python3
"""
65_termux_environment_checker.py - Validates a Termux mobile environment.
Day 9: Forensics and Hardening
"""

import os
import shutil

def check_termux():
    print("--- Termux Environment Validation ---")
    
    # Check if running in Termux (usually has /data/data/com.termux)
    is_termux = os.path.exists("/data/data/com.termux")
    print(f"Running in Termux: {'Yes' if is_termux else 'No'}")

    required_tools = ["nmap", "git", "python", "curl", "ssh"]
    print("\n--- Tool Check ---")
    for tool in required_tools:
        path = shutil.which(tool)
        status = f"[OK] Found at {path}" if path else "[MISSING]"
        print(f"{tool:8}: {status}")

    critical_paths = [
        "/data/data/com.termux/files/home",
        "/data/data/com.termux/files/usr/bin"
    ]
    print("\n--- Path Validation ---")
    for p in critical_paths:
        exists = os.path.exists(p)
        print(f"{p}: {'[EXISTS]' if exists else '[NOT FOUND]'}")

if __name__ == "__main__":
    check_termux()
