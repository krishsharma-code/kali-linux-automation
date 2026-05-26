#!/usr/bin/env python3
"""
24_resource_spike_alert.py
Day 5: Security Auditing & Log Analysis
Description: Monitors system resources and alerts on spikes (potential DoS or cryptojacking).
"""

import psutil
import time

# Thresholds in percentage
CPU_THRESHOLD = 80.0
RAM_THRESHOLD = 85.0

def monitor_resources():
    print(f"[*] Monitoring System Resources (Thresholds: CPU={CPU_THRESHOLD}%, RAM={RAM_THRESHOLD}%)...")
    print("[*] Press Ctrl+C to stop.")
    
    try:
        while True:
            cpu_usage = psutil.cpu_percent(interval=1)
            ram_usage = psutil.virtual_memory().percent
            
            status = "OK"
            alert_msg = ""

            if cpu_usage > CPU_THRESHOLD:
                status = "!!! ALERT !!!"
                alert_msg += f" [High CPU: {cpu_usage}%]"
            
            if ram_usage > RAM_THRESHOLD:
                status = "!!! ALERT !!!"
                alert_msg += f" [High RAM: {ram_usage}%]"

            current_time = time.strftime("%H:%M:%S")
            print(f"[{current_time}] CPU: {cpu_usage:5.1f}% | RAM: {ram_usage:5.1f}% | Status: {status}{alert_msg}")
            
            if status != "OK":
                print(f"    [!] INVESTIGATE: Potential resource exhaustion or malicious process detected.")

            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Resource monitoring stopped.")

if __name__ == "__main__":
    monitor_resources()
