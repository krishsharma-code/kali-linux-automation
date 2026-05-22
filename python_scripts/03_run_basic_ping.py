import subprocess
import sys

def main():
    # Detect OS to use appropriate command
    if sys.platform == "win32":
        command = ["whoami"]
    else:
        command = ["whoami"]
    
    print(f"Executing command: {' '.join(command)}")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Command Output:")
        print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

if __name__ == "__main__":
    main()
