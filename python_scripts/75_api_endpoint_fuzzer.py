import requests

def fuzz_api(base_url, wordlist):
    """Fuzzes a mock target URL with common API paths looking for 200 OK responses."""
    print(f"[*] Starting API Fuzzer on: {base_url}")
    print("-" * 30)
    
    found_endpoints = []
    
    for path in wordlist:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            # Mocking the request check
            # In real usage, this would be: response = requests.get(url, timeout=2)
            # For this exercise, we simulate finding specific endpoints
            if path in ["api/v1/users", "api/v1/config", "admin/login"]:
                print(f"[+] FOUND: {url} (Status: 200)")
                found_endpoints.append(url)
            else:
                # print(f"[-] {url} (Status: 404)")
                pass
        except Exception as e:
            print(f"[!] Error checking {url}: {e}")
            
    print("-" * 30)
    print(f"[*] Fuzzing complete. Total endpoints discovered: {len(found_endpoints)}")

if __name__ == "__main__":
    target = "https://api.mock-target.io"
    # Common API paths to fuzz
    common_paths = [
        "api/v1/users",
        "api/v1/health",
        "api/v1/admin",
        "api/v2/auth",
        "config",
        "env",
        "admin/login",
        "swagger",
        "v1/docs"
    ]
    fuzz_api(target, common_paths)
