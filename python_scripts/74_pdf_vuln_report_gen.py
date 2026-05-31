import datetime

def generate_report(target, vulns):
    """Generates a vulnerability report in text format (simulating a PDF generator)."""
    report_name = f"Vuln_Report_{target}_{datetime.date.today()}.txt"
    
    content = [
        "=" * 50,
        "VULNERABILITY ASSESSMENT REPORT",
        "=" * 50,
        f"Target: {target}",
        f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 50,
        "VULNERABILITIES FOUND:",
    ]
    
    if not vulns:
        content.append("No critical vulnerabilities found.")
    else:
        for v in vulns:
            content.append(f"\n[!] {v['id']}: {v['name']}")
            content.append(f"    Severity: {v['severity']}")
            content.append(f"    Description: {v['desc']}")
            content.append(f"    Remediation: {v['fix']}")

    content.append("\n" + "=" * 50)
    content.append("END OF REPORT")
    
    with open(report_name, "w") as f:
        f.write("\n".join(content))
    
    print(f"[+] Report generated successfully: {report_name}")

if __name__ == "__main__":
    # Mock findings
    target_site = "enterprise-mock-corp.com"
    findings = [
        {
            "id": "CVE-2021-44228", 
            "name": "Log4Shell", 
            "severity": "CRITICAL", 
            "desc": "Remote code execution via log message expansion.", 
            "fix": "Update Log4j to version 2.17.1 or higher."
        },
        {
            "id": "SEC-001", 
            "name": "Missing HSTS Header", 
            "severity": "LOW", 
            "desc": "HTTP Strict Transport Security is not enabled.", 
            "fix": "Enable HSTS in server configuration."
        }
    ]
    
    generate_report(target_site, findings)
