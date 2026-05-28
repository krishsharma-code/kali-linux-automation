import os

def generate_ufw_rules(bad_ips_path, output_script):
    """
    Reads a list of bad IPs and generates a shell script with UFW block commands.
    """
    if not os.path.exists(bad_ips_path):
        print(f"[-] Error: IP list {bad_ips_path} not found.")
        return

    print(f"[*] Reading malicious IPs from {bad_ips_path}...")
    with open(bad_ips_path, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        print("[!] No IPs found in the list.")
        return

    print(f"[*] Generating UFW block script: {output_script}")
    with open(output_script, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Auto-generated UFW Block Script\n")
        f.write("# Day 7: Defensive Monitoring\n\n")
        
        for ip in ips:
            # Command to block incoming traffic from specific IP
            command = f"sudo ufw deny from {ip} to any"
            f.write(f"{command}\n")
            print(f"  [+] Added block for: {ip}")

    # Make the generated script executable
    # os.chmod(output_script, 0o755)
    print(f"\n[SUCCESS] Firewall block script generated: {output_script}")
    print("[INFO] Run 'bash " + output_script + "' to apply rules.")

if __name__ == "__main__":
    # Mock malicious IP list
    mock_ips = "malicious_ips.txt"
    with open(mock_ips, "w") as f:
        f.write("192.168.1.100\n203.0.113.10\n45.33.32.156\n")
    
    block_script = "apply_blocks.sh"
    generate_ufw_rules(mock_ips, block_script)
    
    # Cleanup mock files for demonstration
    # os.remove(mock_ips)
    # os.remove(block_script)
