import os

def parse_auth_log(log_path):
    """
    Parses a mock auth.log file to identify and count failed SSH login attempts.
    """
    failed_attempts = {}

    if not os.path.exists(log_path):
        print(f"[-] Error: Log file {log_path} not found.")
        return

    print(f"[*] Analyzing Log: {log_path}")
    with open(log_path, 'r') as file:
        for line in file:
            # Look for common failed login patterns in SSH logs
            if "Failed password" in line or "authentication failure" in line:
                # Basic parsing to extract IP (simplistic for mock demonstration)
                parts = line.split()
                try:
                    # In a standard auth.log, the IP often follows 'from'
                    if 'from' in parts:
                        ip_index = parts.index('from') + 1
                        ip = parts[ip_index]
                        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                except (ValueError, IndexError):
                    continue

    print("\n[!] SUSPICIOUS ACTIVITY REPORT")
    print("-" * 30)
    for ip, count in failed_attempts.items():
        status = "CRITICAL" if count > 5 else "WARNING"
        print(f"[{status}] IP: {ip} | Failed Attempts: {count}")

def generate_mock_log(log_path):
    """Creates a mock auth.log for demonstration."""
    mock_data = [
        "May 28 10:00:01 kali sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2\n",
        "May 28 10:01:05 kali sshd[1235]: Failed password for admin from 192.168.1.50 port 22 ssh2\n",
        "May 28 10:02:10 kali sshd[1236]: Accepted password for user1 from 192.168.1.10 port 22 ssh2\n",
        "May 28 10:05:15 kali sshd[1237]: Failed password for root from 203.0.113.5 port 22 ssh2\n",
        "May 28 10:06:20 kali sshd[1238]: Failed password for root from 192.168.1.50 port 22 ssh2\n",
    ]
    with open(log_path, 'w') as f:
        f.writelines(mock_data)

if __name__ == "__main__":
    mock_log = "mock_auth.log"
    generate_mock_log(mock_log)
    parse_auth_log(mock_log)
    # Cleanup mock log after run (optional)
    # os.remove(mock_log)
