import json

def lookup_cve(cve_id):
    """Queries a mock local JSON database for CVE details based on user input."""
    # Mock CVE Database
    mock_db = {
        "CVE-2021-44228": {
            "name": "Log4Shell",
            "severity": "Critical",
            "score": 10.0,
            "description": "Apache Log4j2 remote code execution vulnerability."
        },
        "CVE-2017-0144": {
            "name": "EternalBlue",
            "severity": "Critical",
            "score": 9.3,
            "description": "Windows SMB remote code execution vulnerability used in WannaCry."
        },
        "CVE-2014-0160": {
            "name": "Heartbleed",
            "severity": "High",
            "score": 7.5,
            "description": "OpenSSL information leak vulnerability."
        }
    }
    
    print(f"[*] Searching database for {cve_id}...")
    result = mock_db.get(cve_id.upper())
    
    if result:
        print(f"[+] Found Match: {result['name']}")
        print(f"    Severity: {result['severity']} (Score: {result['score']})")
        print(f"    Description: {result['description']}")
    else:
        print(f"[-] No record found for {cve_id}.")

if __name__ == "__main__":
    print("--- CVE Database Lookup Tool ---")
    user_input = input("Enter CVE ID (e.g., CVE-2021-44228): ").strip()
    lookup_cve(user_input)
