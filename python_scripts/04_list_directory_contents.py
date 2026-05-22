import subprocess
import sys

def main():
    if sys.platform == "win32":
        command = ["cmd", "/c", "dir", "/a"]
    else:
        command = ["ls", "-la"]
    
    print(f"Executing command: {' '.join(command)}")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Directory Contents:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

if __name__ == "__main__":
    main()
