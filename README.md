# 🐉 Kali Linux Automation Toolkit

**A curated collection of 145 Bash and Python scripts for local system administration, network reconnaissance, defensive monitoring, and security hardening — built for a Linux/Kali environment.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Bash](https://img.shields.io/badge/Bash-4%2B-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Scripts](https://img.shields.io/badge/scripts-145-informational)](#-script-index)
[![Last commit](https://img.shields.io/github/last-commit/krishsharma-code/kali-linux-automation)](https://github.com/krishsharma-code/kali-linux-automation/commits/main)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Usage](#-usage)
- [Script Index](#-script-index)
  - [Day 1–2 · Linux Foundations & File Operations](#day-12--linux-foundations--file-operations)
  - [Day 3–4 · Network Reconnaissance & Web Recon](#day-34--network-reconnaissance--web-recon)
  - [Day 5–7 · Defensive Monitoring & Log Analysis](#day-57--defensive-monitoring--log-analysis)
  - [Day 8–10 · Vulnerability Scanning & Forensics](#day-810--vulnerability-scanning--forensics)
  - [Day 11–12 · Local System & Network Enumeration](#day-1112--local-system--network-enumeration)
  - [Day 13–15 · System Hardening & Container Security](#day-1315--system-hardening--container-security)
- [Repository Conventions](#-repository-conventions)
- [Contributing](#-contributing)
- [Ethical Disclaimer](#-ethical-disclaimer)
- [License](#-license)

---

## 📌 Overview

This toolkit documents a progressive journey through Linux automation and defensive security. It collects **145 self-contained scripts** — **64 Python** and **81 Bash** — organised into two directories and grouped by learning module.

- **`python_scripts/`** — Python 3 utilities for parsing, enumeration, threading, and reporting.
- **`bash_scripts/`** — POSIX-friendly shell utilities for quick system and network tasks.

Every script is small, readable, and focused on a single job. Unless a script explicitly changes system state (and warns you first), the default behaviour is **read-only and non-destructive**.

> ⚠️ **Educational use only.** See the [Ethical Disclaimer](#-ethical-disclaimer) before running anything against a system you do not own.

---

## 🗂️ Repository Structure

```text
kali-linux-automation/
├── bash_scripts/              # 81 shell utilities
│   ├── file_permissions.sh
│   ├── netstat_active_ports.sh
│   ├── docker_container_audit.sh
│   └── ...                    # descriptive snake_case names
├── python_scripts/            # 64 Python utilities
│   ├── create_system_directory.py
│   ├── ping_sweep_threaded.py
│   ├── termux_environment_mapper.py
│   └── ...                    # descriptive snake_case names
├── .github/
│   ├── ISSUE_TEMPLATE/        # bug report + new-script request templates
│   ├── workflows/ci.yml       # CI (lint / syntax checks)
│   └── pull_request_template.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE                    # MIT
└── README.md
```

---

## ✅ Prerequisites

| Requirement | Version | Notes |
| :--- | :--- | :--- |
| **Python** | 3.8+ | For everything under `python_scripts/`. |
| **Bash** | 4.0+ | For everything under `bash_scripts/`. |
| **coreutils / iproute2** | current | `ip`, `ss`, `grep`, `awk`, `ps`, `find` — present on any Kali install. |

**Optional third-party tools** — only needed by the scripts that wrap them:

| Tool | Used by | Install |
| :--- | :--- | :--- |
| `nmap` | port-scan and vuln wrappers | `sudo apt install nmap` |
| `nikto` | `nikto_web_scanner_wrapper.sh` | `sudo apt install nikto` |
| `gobuster` | `gobuster_automator.sh` | `sudo apt install gobuster` |
| `whois`, `dnsutils` | DNS/whois enumeration | `sudo apt install whois dnsutils` |
| `netcat` (`nc`) | banner grabbing | `sudo apt install netcat-traditional` |
| `docker` | `docker_container_audit.sh` | per Docker docs |
| `scapy` (pip) | `packet_sniffer_scapy_basic.py` | `pip install scapy` |
| `requests` (pip) | web-recon scripts | `pip install requests` |

Scripts degrade gracefully when an optional tool is missing — they print a clear notice instead of failing hard.

---

## 🚀 Usage

### Running Python scripts

```bash
cd python_scripts
python3 ping_sweep_threaded.py
```

### Running Bash scripts

```bash
cd bash_scripts
chmod +x sys_info.sh
./sys_info.sh
```

### Example: run a utility and capture its report

```bash
# Grant execute permission once, then run from the repo root:
chmod +x bash_scripts/docker_container_audit.sh
./bash_scripts/docker_container_audit.sh --all --output docker_audit.txt
```

Some scripts accept flags — pass `--help` to see the supported options, for example:

```bash
./bash_scripts/docker_container_audit.sh --help
```

---

## 🧭 Script Index

Each table lists the script filename, its functional category, and a one-line description. Filenames use descriptive `snake_case`, and the tables group scripts by learning module rather than by number.

### Day 1–2 · Linux Foundations & File Operations

| Script | Category | Description |
| :--- | :--- | :--- |
| `create_system_directory.py` | Foundations | Scaffolds an organised system directory tree for the toolkit. |
| `write_sample_logs.py` | Foundations | Generates sample log files for testing monitoring and parsing scripts. |
| `run_basic_ping.py` | Networking | Simple connectivity check against common targets such as Google DNS. |
| `list_directory_contents.py` | File Ops | Walks and prints a directory structure for inspection. |
| `file_permissions.sh` | File Ops | Demonstrates `chmod` and execution-right management. |
| `connectivity_check.sh` | Networking | Basic connectivity and address discovery with `ping`. |
| `ip_recon.sh` | Networking | Extracts the local IP address using `ip addr` and `grep`. |
| `file_ops.sh` | File Ops | Automates `touch`, `cp`, `mv`, and `rm` operations. |
| `grep_search.sh` | Text Processing | Pattern matching and search within log files using `grep`. |
| `system_updater.sh` | Maintenance | Automated system update and package management. |
| `user_recon.sh` | Recon | Reports on the current user's sessions and privileges. |
| `log_reader.sh` | Log Analysis | Reads file segments with `cat`, `head`, and `tail`. |
| `hidden_files.sh` | File Ops | Explores hidden-file creation and discovery (`ls -la`). |
| `process_hunter.sh` | Process Management | Tracks and filters background processes with `ps aux`. |
| `project_directory_setup.sh` | File Ops | Quickly scaffolds a standard project directory structure. |
| `disk_monitor.sh` | Monitoring | Reports disk-space usage in a human-readable format. |
| `file_backup.sh` | Backup | Creates a `.bak` backup copy of a chosen file. |
| `ip_fetcher.sh` | Networking | Detects and prints the local IP address. |
| `local_net_analyzer.sh` | Networking | Consolidated report of IP info, routing tables, and listening services. |
| `mass_file_creator.sh` | File Ops | Demonstrates bulk file creation in a single pass. |
| `network_ping.sh` | Networking | Checks connectivity to a host with a 3-packet ping. |
| `open_ports.sh` | Networking | Lists all active listening network ports. |
| `sys_info.sh` | System Info | Prints basic OS and kernel information. |
| `user_greet.sh` | Utilities | Displays the current user and time as a friendly greeting. |

### Day 3–4 · Network Reconnaissance & Web Recon

| Script | Category | Description |
| :--- | :--- | :--- |
| `nmap_subprocess_wrapper.py` | Network Recon | Runs and parses basic Nmap scans via `subprocess`. |
| `socket_banner_grabber.py` | Network Recon | Low-level socket connection to grab service banners. |
| `ping_sweep_threaded.py` | Network Recon | Multi-threaded ping sweep for subnet host discovery. |
| `mac_address_vendor.py` | Network Recon | OUI-based MAC address vendor lookup (mock dataset). |
| `local_network_mapper.py` | Network Recon | Simulates mapping the devices on a local subnet. |
| `ping_sweeper.py` | Network Recon | Uses `subprocess` to find live hosts across a /24 subnet. |
| `basic_port_scanner.py` | Network Recon | Socket-based TCP scan of common ports. |
| `banner_grabber.py` | Network Recon | Connects to ports and retrieves service banners. |
| `nmap_xml_parser.py` | Network Recon | Extracts open ports and services from Nmap XML output. |
| `mac_address_vendor_lookup.py` | Network Recon | Resolves device vendors from MAC addresses via lookup APIs. |
| `requests_fuzzer.py` | Web Recon | Basic directory fuzzing with the `requests` library. |
| `subdomain_bruteforce.py` | Web Recon | Tests a subdomain wordlist against a target domain. |
| `http_header_analyzer.py` | Web Recon | Extracts server info and security headers. |
| `robots_txt_parser.py` | Web Recon | Fetches and parses disallowed paths from `robots.txt`. |
| `web_crawler_basic.py` | Web Recon | Extracts all `href` links from a webpage. |
| `http_header_inspector.py` | Web Recon | Pulls HTTP headers to fingerprint server versions. |
| `robots_txt_scraper.py` | Web Recon | Downloads and parses `robots.txt` to surface hidden paths. |
| `subdomain_bruteforcer_mock.py` | Web Recon | Wordlist-driven subdomain testing (mock resolver). |
| `ssl_cert_checker.py` | Web Recon | Reads an SSL/TLS certificate's details and expiry date. |
| `directory_fuzzer_lite.py` | Web Recon | Probes common admin/login paths for `200 OK` responses. |
| `netstat_active_ports.sh` | Network Recon | Filters `netstat` output for `LISTEN`-state services. |
| `ss_monitor.sh` | Network Recon | Socket statistics via the `ss` command. |
| `nmap_fast_scan.sh` | Network Recon | Automates a fast-mode Nmap scan against a target. |
| `route_tracer.sh` | Network Recon | Path discovery using `traceroute`. |
| `arp_table_reader.sh` | Network Recon | Formats and displays the local ARP cache. |
| `quick_nmap_scan.sh` | Network Recon | Fast scan of the top 100 common ports. |
| `full_tcp_syn_scan.sh` | Network Recon | Stealthy SYN scan across all 65,535 ports. |
| `dns_enumeration.sh` | Network Recon | Forward and reverse DNS lookup automation. |
| `arp_discovery.sh` | Network Recon | Identifies local devices using ARP requests. |
| `ssl_cert_checker.sh` | Network Recon | Checks SSL certificate expiry and details. |
| `nmap_quick_scan_wrapper.sh` | Enumeration | Automates an Nmap fast scan and writes clean results to a file. |
| `dns_enum_tool.sh` | Enumeration | Extracts A, MX, and TXT records with `host` and `dig`. |
| `whois_ip_lookup.sh` | Enumeration | Runs `whois` across a list of IPs for organisational data. |
| `ping_sweep_subnet.sh` | Enumeration | Simple loop to ping every host in a /24 subnet. |
| `banner_grabber_netcat.sh` | Enumeration | Uses `nc` to connect to a port and grab its banner. |
| `curl_header_grabber.sh` | Web Recon | Fast `curl` one-liner to inspect response headers. |
| `gobuster_automator.sh` | Web Recon | Automates a `gobuster` dir scan with standard wordlists. |
| `nikto_fast_scan.sh` | Web Recon | Wrapper to run the Nikto web scanner. |
| `wget_mirror.sh` | Web Recon | Downloads and mirrors a basic website. |
| `whois_dns_lookup.sh` | Web Recon | Combines `whois`, `dig`, and `nslookup` for full target info. |

### Day 5–7 · Defensive Monitoring & Log Analysis

| Script | Category | Description |
| :--- | :--- | :--- |
| `apache_log_parser.py` | Log Analysis | Parses server access logs for 404/500 errors. |
| `failed_login_detector.py` | Log Analysis | Scans `auth.log` for repeated SSH failures. |
| `file_integrity_monitor.py` | Integrity | Monitors critical files using SHA-256 hashes. |
| `active_ports_analyzer.py` | Monitoring | Lists local listening ports and their owning processes. |
| `resource_spike_alert.py` | Monitoring | Watches CPU/RAM usage for anomalies. |
| `auth_log_parser.py` | Log Analysis | Counts failed SSH logins from a mock `auth.log`. |
| `file_integrity_watcher.py` | Integrity | Hashes critical files and alerts on changes. |
| `malicious_ip_blocker.py` | Defense | Reads bad IPs and generates UFW block commands. |
| `suspicious_process_hunter.py` | Monitoring | Flags processes running from unusual directories like `/tmp`. |
| `yara_rule_generator.py` | Signatures | Generates basic YARA rule syntax for signature matching. |
| `check_root_privileges.sh` | Privilege Audit | Verifies root/sudo escalation rights. |
| `find_suid_binaries.sh` | Privilege Audit | Locates SUID/SGID files for auditing. |
| `backup_critical_configs.sh` | Backup | Automates secure backup of `/etc` files. |
| `ssh_config_auditor.sh` | Hardening | Audits `sshd_config` against hardening rules. |
| `firewall_status_checker.sh` | Firewall | Monitors UFW/iptables rules and status. |
| `active_connections_monitor.sh` | Monitoring | Lists established connections and their PIDs. |
| `suid_guid_finder.sh` | Privilege Audit | Finds SUID/GUID files to audit privilege-escalation risk. |
| `firewall_status_check.sh` | Firewall | Checks UFW/iptables status and dumps rules to a log. |
| `cronjob_auditor.sh` | Persistence Audit | Lists scheduled cron jobs to check for persistence. |
| `system_baseline_snapshot.sh` | Baseline | Snapshots installed packages and running services. |

### Day 8–10 · Vulnerability Scanning & Forensics

| Script | Category | Description |
| :--- | :--- | :--- |
| `ssh_log_analyzer.py` | Forensics | Extracts IPs with repeated failed SSH logins from a mock `auth.log`. |
| `malware_hash_checker.py` | Forensics | Hashes files in a directory and compares them to known signatures. |
| `packet_sniffer_scapy_basic.py` | Forensics | Captures and summarises local packets with Scapy. |
| `steganography_detector.py` | Forensics | Detects data appended after an image's end-of-file marker. |
| `termux_environment_checker.py` | Environment | Validates packages, tools, and paths for a Termux environment. |
| `cve_database_lookup.py` | Vuln Scanning | Queries a local JSON database for CVE details. |
| `port_scanner_banner_grab.py` | Vuln Scanning | Multi-threaded port scan with service banner grabbing. |
| `subdomain_takeover_check.py` | Vuln Scanning | Checks subdomains for dangling-CNAME takeover risk. |
| `vulnerability_report_generator.py` | Reporting | Formats scan results into a readable text/PDF report. |
| `api_endpoint_fuzzer.py` | Vuln Scanning | Fuzzes common API paths and reports `200 OK` responses. |
| `kali_usb_persistence_check.sh` | Forensics | Verifies partition health and mount status of a persistent Kali USB. |
| `outbound_connection_monitor.sh` | Forensics | Logs suspicious outbound connections via `ss`/`netstat`. |
| `file_integrity_monitor.sh` | Forensics | Cron-friendly hashing of critical files with change alerts. |
| `firewall_iptables_setup.sh` | Hardening | Configures basic defensive iptables rules (default-drop inbound). |
| `suspicious_process_hunter.sh` | Forensics | Flags high-resource or suspiciously-located processes. |
| `nmap_vuln_automator.sh` | Vuln Scanning | Runs Nmap with `--script vuln` and formats the output. |
| `nikto_web_scanner_wrapper.sh` | Vuln Scanning | Automates Nikto scans and saves timestamped output. |
| `wp_scan_updater.sh` | Vuln Scanning | Updates the WPScan database and runs basic enumeration. |
| `ssh_audit_tool.sh` | Vuln Scanning | Checks SSH config for weak ciphers and root login. |
| `daily_security_summary.sh` | Reporting | Compiles prior script output into a daily summary. |

### Day 11–12 · Local System & Network Enumeration

| Script | Category | Description |
| :--- | :--- | :--- |
| `passwd_file_analyzer.py` | Local Enumeration | Reads `/etc/passwd` and lists interactive-shell users. |
| `cron_job_parser.py` | Local Enumeration | Parses crontab files to surface risky scheduled tasks. |
| `log_file_monitor.py` | Local Enumeration | Tails a mock `auth.log` and alerts on failed SSH logins. |
| `file_hash_checker.py` | Local Enumeration | Hashes critical binaries to check for tampering. |
| `network_interface_auditor.py` | Network Enumeration | Lists active interfaces and checks for promiscuous mode. |
| `subnet_mask_parser.py` | Network Enumeration | Parses CIDR notation into network range and host limits. |
| `live_host_ping_sweep.py` | Network Enumeration | Threaded ICMP sweep to discover active nodes. |
| `mac_address_spoof_automator.py` | Network Enumeration | Rotates hardware MAC addresses for anonymity. |
| `dns_recon_resolver.py` | Network Enumeration | Resolves A, MX, and TXT records for target mapping. |
| `socket_banner_grabber_cli.py` | Network Enumeration | Fingerprints service versions via low-level sockets. |
| `suid_binary_finder.sh` | Local Enumeration | Finds all SUID files on the system and saves the list. |
| `open_ports_enumerator.sh` | Local Enumeration | Lists listening ports with their associated PIDs. |
| `sudo_privilege_checker.sh` | Local Enumeration | Runs `sudo -l` and parses NOPASSWD entries. |
| `system_info_gatherer.sh` | Local Enumeration | Collects kernel, hostname, and OS info into one file. |
| `clear_logs_simulator.sh` | Local Enumeration | Demonstrates history/wtmp clearing (defensive awareness only). |
| `new_connection_alert.sh` | Network Enumeration | Alerts on new unauthorised established TCP connections. |
| `iptables_firewall_reset.sh` | Network Enumeration | Resets firewall rules to a secure default-deny posture. |
| `arp_cache_poison_detector.sh` | Network Enumeration | Flags duplicate MACs in the ARP table to warn of spoofing. |
| `wireless_interface_auditor.sh` | Network Enumeration | Evaluates wireless card modes and monitor capability. |
| `network_recon_bundle.sh` | Network Enumeration | Aggregates interface, routing, and DNS data into a forensic dump. |

### Day 13–15 · System Hardening & Container Security

| Script | Category | Description |
| :--- | :--- | :--- |
| `process_anomaly_hunter.py` | Hardening | Inspects `/proc` for unlinked binaries and odd execution paths. |
| `shadow_file_integrity.py` | Hardening | Audits `/etc/shadow` permissions and ownership. |
| `netstat_log_parser.py` | Hardening | Detects unprivileged ports bound to public interfaces. |
| `systemd_service_auditor.py` | Hardening | Flags services running from non-standard or risky paths. |
| `api_key_leak_scanner.py` | Hardening | Regex-scans code for hardcoded API keys and secrets. |
| `subnet_ping_sweeper.py` | Network Security | Rapid multi-threaded ping sweep for host discovery. |
| `port_banner_grabber.py` | Network Security | Service fingerprinting and banner grabbing for vulnerability mapping. |
| `mac_address_spoofer.py` | Network Security | Randomises and assigns new MAC addresses to interfaces. |
| `dns_zone_transfer_check.py` | Network Security | Attempts AXFR transfers to map internal DNS topology. |
| `termux_environment_mapper.py` | Environment Security | Audits permissions and tools in mobile Termux environments. |
| `ufw_rules_compiler.sh` | Hardening | Compiles net rules, clears dangling entries, hardens conntrack. |
| `ssh_bruteforce_defense.sh` | Hardening | Dynamically blacklists malicious IPs from auth logs. |
| `kernel_parameter_tuner.sh` | Hardening | Hardens kernel parameters against spoofing and redirects. |
| `untrusted_ppa_purger.sh` | Hardening | Verifies repository signatures and purges untrusted sources. |
| `auditd_report_aggregator.sh` | Hardening | Compiles core logs and snapshots into a locked report. |
| `iptables_reset_secure.sh` | Hardening | Applies a strict default-drop iptables policy. |
| `rogue_process_killer.sh` | Hardening | Terminates high-CPU background processes without a TTY. |
| `cronjob_audit_reporter.sh` | Hardening | Scans system/user cronjobs for suspicious persistence. |
| `usb_autorun_blocker.sh` | Hardening | Blocks automated mounting and execution from USB devices. |
| `kali_update_cleaner.sh` | Maintenance | Deep maintenance: system updates and package-cache cleaning. |
| `docker_container_audit.sh` | Container Security | Read-only audit of containers for privileged mode, host namespaces, and risky mounts. |

---

## 🧱 Repository Conventions

- **Descriptive names.** Every script uses a clear `snake_case` filename that states what it does (e.g. `file_integrity_monitor.py`); there are no numeric prefixes.
- **Self-contained.** Each script runs on its own — no shared library or build step.
- **Safe defaults.** Destructive actions require explicit confirmation or an opt-in flag; audits and monitors are read-only.
- **Readable output.** Progress and results are prefixed with `[*]` (info), `[+]` (success), and `[!]` (warning) for quick scanning.
- **`--help` where useful.** Scripts that take arguments document them behind a `--help` flag.

---

## 🤝 Contributing

Contributions are welcome — new scripts, bug fixes, and documentation improvements alike.

1. **Read [`CONTRIBUTING.md`](CONTRIBUTING.md)** for the full guidelines.
2. **Branch** from `main` (`git checkout -b feat/my-script`).
3. **Match the conventions** above: shebang line, numeric prefix, `--help` support, safe defaults, and comments for any non-obvious logic.
4. **Use [Conventional Commits](https://www.conventionalcommits.org/)** (`feat:`, `fix:`, `docs:`, `chore:`).
5. **Update this README's script index** in the correct module section when you add a file.
6. **Never commit secrets**, API keys, tokens, or credentials.
7. **Open a pull request** using the provided template.

Please also read the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## 🔒 Ethical Disclaimer

This toolkit is provided strictly for **education, local system administration, and authorised security testing**. Its reconnaissance, scanning, and enumeration scripts must only be run against **systems you own or have explicit, documented written permission to test**.

- Unauthorised scanning, access, or interference with systems you do not own is **illegal** in most jurisdictions and is expressly prohibited.
- Several scripts change system state (firewall rules, kernel parameters, MAC addresses, package sources). Review them before running, and never execute them on production systems without a tested rollback plan.
- You are solely responsible for how you use these tools. The author assumes **no liability** for misuse or for any damage caused.

If you are unsure whether you are authorised, **you are not** — stop and ask the system owner.

---

## 📄 License

Released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright © 2026 Krish Sharma.
