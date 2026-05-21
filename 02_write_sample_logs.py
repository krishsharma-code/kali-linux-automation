import os

def main():
    directory = "secure_logs"
    file_path = os.path.join(directory, "system.log")
    
    # Ensure directory exists (from previous script logic)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    logs = [
        "INFO: 2026-05-21 10:00:00 - System initialization started.",
        "WARNING: 2026-05-21 10:05:00 - Low disk space on /dev/sda1.",
        "ERROR: 2026-05-21 10:10:00 - Failed to connect to remote server."
    ]
    
    with open(file_path, "w") as f:
        for line in logs:
            f.write(line + "\n")
            
    print(f"Success: Sample logs written to '{file_path}'.")

if __name__ == "__main__":
    main()
