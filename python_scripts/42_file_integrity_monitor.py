import hashlib
import os
import time

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def monitor_files(file_list):
    """Monitors a list of files for changes in their SHA-256 hash."""
    baseline = {}
    
    print("[*] Establishing Baseline Hashes...")
    for file_path in file_list:
        file_hash = calculate_sha256(file_path)
        if file_hash:
            baseline[file_path] = file_hash
            print(f"[+] Baseline set for {file_path}: {file_hash[:16]}...")

    print("\n[*] Monitoring Active... (Press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(5)
            for file_path in file_list:
                current_hash = calculate_sha256(file_path)
                
                if current_hash is None:
                    print(f"[!] ALERT: File Deleted: {file_path}")
                    continue

                if current_hash != baseline.get(file_path):
                    print(f"[!!!] ALERT: File Modified: {file_path}")
                    print(f"      Old Hash: {baseline.get(file_path)}")
                    print(f"      New Hash: {current_hash}")
                    # Update baseline after alert to prevent continuous alerting
                    baseline[file_path] = current_hash
    except KeyboardInterrupt:
        print("\n[*] Monitoring Stopped.")

if __name__ == "__main__":
    # For demonstration, we'll create and monitor a mock config file
    mock_config = "mock_system.conf"
    with open(mock_config, "w") as f:
        f.write("SETTING_A=TRUE\nSETTING_B=FALSE")
    
    # In a real scenario, this would be a list of critical system files
    files_to_watch = [mock_config]
    
    print("[INFO] This script will monitor 'mock_system.conf'. Try modifying it in another terminal!")
    # monitor_files(files_to_watch) # Commented out for automated execution safety
    
    # Simple one-time check demonstration
    initial = calculate_sha256(mock_config)
    print(f"Initial Hash: {initial}")
    
    with open(mock_config, "a") as f:
        f.write("\nSETTING_C=MALICIOUS_INJECT")
    
    final = calculate_sha256(mock_config)
    print(f"Final Hash:   {final}")
    
    if initial != final:
        print("[!] SUCCESS: Integrity violation detected.")
    
    # Cleanup
    if os.path.exists(mock_config):
        os.remove(mock_config)
