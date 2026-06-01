#!/usr/bin/env python3
"""
82_cron_job_parser.py
Day 11: Local Enumeration
Description: Simulates parsing crontab files to identify potentially vulnerable scheduled tasks.
"""

import glob
import os

def parse_cron_jobs():
    cron_locations = [
        "/etc/crontab",
        "/etc/cron.d/*",
        "/var/spool/cron/crontabs/*"
    ]
    
    print("[*] Auditing Scheduled Tasks (Cron Jobs) for vulnerabilities...")
    print("-" * 60)

    found_any = False
    for loc in cron_locations:
        files = glob.glob(loc)
        for cron_file in files:
            if os.path.isfile(cron_file):
                found_any = True
                print(f"[+] Checking: {cron_file}")
                try:
                    with open(cron_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Basic vulnerability check: look for writable scripts or paths
                                if '/' in line:
                                    print(f"    [!] Potential Task: {line}")
                                    # Audit logic could go deeper here (checking permissions of paths)
                except Exception as e:
                    print(f"    [-] Could not read {cron_file}: {e}")

    if not found_any:
        print("[-] No system cron files found or accessible. This script is intended for Linux environments.")

if __name__ == "__main__":
    parse_cron_jobs()
