import os
import re

def scan_for_secrets(directory):
    """
    Regex-driven string analyzer that scans code workspaces to flag 
    leaked hardcoded authorization variables.
    """
    print(f"=== API Key Leak Scanner ===")
    print(f"[*] Scanning directory: {directory}")

    # Common patterns for secrets
    patterns = {
        "Generic API Key": r"(?i)(api[_-]key|apikey|auth[_-]token|access[_-]token)[\s:=]+['\"]([a-zA-Z0-9]{16,})['\"]",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}"
    }

    leaks_found = 0
    for root, dirs, files in os.walk(directory):
        # Skip hidden directories like .git
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip binary files
            if file.endswith(('.png', '.jpg', '.exe', '.pyc', '.zip')):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for name, pattern in patterns.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            print(f"[!] LEAK DETECTED [{name}] in {file_path}")
                            print(f"    Match: {match.group(0)[:30]}...")
                            leaks_found += 1
            except Exception as e:
                print(f"[!] Could not read {file_path}: {e}")

    if leaks_found == 0:
        print("[+] No hardcoded API keys or secrets detected.")
    else:
        print(f"[*] Scan complete. {leaks_found} potential leaks found.")

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    import sys
    scan_for_secrets(target_dir)
