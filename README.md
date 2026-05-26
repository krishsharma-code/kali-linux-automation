# Kali Linux Automation Toolkit

A collection of Python and Bash scripts designed for local system and network automation. This toolkit provides utilities for system information gathering, log management, and network analysis, tailored for efficiency in a Linux-style environment.

## 📌 Overview

This repository contains a suite of automation scripts that demonstrate core system administration and network diagnostic tasks. For better maintainability and organization, the tools are categorized into `python_scripts/` and `bash_scripts/` directories.

## 🛠️ Scripts Included

### 🐍 Python Scripts (`python_scripts/`)
- **01_create_system_directory.py**: Automates the creation of organized system directory structures.
- **02_write_sample_logs.py**: Generates sample log files for testing and monitoring practice.
- **03_run_basic_ping.py**: Performs a simple connectivity check against common targets (like Google DNS).
- **04_list_directory_contents.py**: A utility to systematically list and inspect directory structures.
- **10_nmap_subprocess_wrapper.py**: (Day 3 Recon) Uses python to run and parse basic nmap scans.
- **11_socket_banner_grabber.py**: (Day 3 Recon) Low-level socket connection to grab service banners.
- **12_ping_sweep_threaded.py**: (Day 3 Recon) High-speed multi-threaded ping sweep for subnet discovery.
- **13_mac_address_vendor.py**: (Day 3 Recon) Mock script for OUI-based MAC address vendor lookup.
- **14_local_network_mapper.py**: (Day 3 Recon) Simulates mapping devices on a local subnet.
- **15_requests_fuzzer.py**: (Day 4 Web Recon) Basic directory fuzzing using Python requests.
- **16_subdomain_bruteforce.py**: (Day 4 Web Recon) Checking a list of subdomains against a target.
- **17_http_header_analyzer.py**: (Day 4 Web Recon) Extracting Server info and security headers.
- **18_robots_txt_parser.py**: (Day 4 Web Recon) Fetch and parse disallowed paths in robots.txt.
- **19_web_crawler_basic.py**: (Day 4 Web Recon) Extracting all href links from a webpage.
- **20_apache_log_parser.py**: (Day 5 System Defense) Parses server access logs for 404/500 errors.
- **21_failed_login_detector.py**: (Day 5 System Defense) Scans auth.log for repeated SSH failures.
- **22_file_integrity_monitor.py**: (Day 5 System Defense) Monitors critical files using SHA-256 hashes.
- **23_active_ports_analyzer.py**: (Day 5 System Defense) Lists local listening ports and processes.
- **24_resource_spike_alert.py**: (Day 5 System Defense) Monitors CPU/RAM usage for anomalies.

### 🐚 Bash Scripts (`bash_scripts/`)
- **local_net_analyzer.sh**: A powerful network diagnostic script that gathers IP information, routing tables, and active listening services into a consolidated report.
- **sys_info.sh**: Fetches and prints basic OS and kernel information.
- **network_ping.sh**: Checks connectivity to a specific domain with 3 ping packets.
- **ip_fetcher.sh**: Automatically detects and displays the local IP address.
- **dir_setup.sh**: Quickly sets up a standard project directory structure.
- **file_backup.sh**: Creates a secure backup of any file with a '.bak' extension.
- **disk_monitor.sh**: Monitors disk space usage in a human-readable format.
- **open_ports.sh**: Lists all active listening network ports.
- **user_greet.sh**: A friendly greeting script displaying the user and current time.
- **mass_file_creator.sh**: Demonstrates automation by creating multiple test files at once.
- **16_netstat_active_ports.sh**: (Day 3 Recon) Filters netstat output for 'LISTEN' state services.
- **17_ss_monitor.sh**: (Day 3 Recon) Utilizes the 'ss' command for socket statistics.
- **18_nmap_fast_scan.sh**: (Day 3 Recon) Automates a fast-mode Nmap scan on a target.
- **19_route_tracer.sh**: (Day 3 Recon) Path discovery tool using traceroute.
- **20_arp_table_reader.sh**: (Day 3 Recon) Formats and displays the local ARP cache.
- **21_curl_header_grabber.sh**: (Day 4 Web Recon) Fast curl command to inspect headers.
- **22_gobuster_automator.sh**: (Day 4 Web Recon) Automates a gobuster dirb scan with standard wordlists.
- **23_nikto_fast_scan.sh**: (Day 4 Web Recon) Wrapper to run Nikto web scanner.
- **24_wget_mirror.sh**: (Day 4 Web Recon) Script to download and mirror a basic website.
- **25_whois_dns_lookup.sh**: (Day 4 Web Recon) Combines whois, dig, and nslookup for full target info.
- **26_check_root_privileges.sh**: (Day 5 System Defense) Verifies root/sudo escalation rights.
- **27_find_suid_binaries.sh**: (Day 5 System Defense) Locates SUID/SGID files for auditing.
- **28_backup_critical_configs.sh**: (Day 5 System Defense) Automates secure backup of /etc files.
- **29_ssh_config_auditor.sh**: (Day 5 System Defense) Audits sshd_config for hardening rules.
- **30_firewall_status_checker.sh**: (Day 5 System Defense) Monitors UFW/Iptables rules and status.

#### Day 2: File Ops & Network Recon
- **01_file_permissions.sh**: Mastering `chmod` and execution rights.
- **02_network_ping.sh**: Using `ping` for basic connectivity and address discovery.
- **03_ip_recon.sh**: Extracts local IP address using `ip addr` and `grep`.
- **04_file_ops.sh**: Scripting automated `touch`, `cp`, `mv`, and `rm` operations.
- **05_grep_search.sh**: Using `grep` for pattern matching and search within log files.
- **06_system_updater.sh**: Automated system updates and package management.
- **07_user_recon.sh**: Gathering information on current user sessions and privileges.
- **08_log_reader.sh**: Demonstrates reading file segments using `cat`, `head`, and `tail`.
- **09_hidden_files.sh**: Explores hidden file creation and discovery (`ls -la`).
- **10_process_hunter.sh**: Tracks and filters background processes using `ps aux`.

## 🚀 Usage

### Running Python Scripts
Ensure you have Python 3 installed. Navigate to the `python_scripts/` directory and run:
```bash
python3 <script_name>.py
```

### Running Bash Scripts
Before running a bash script, navigate to the `bash_scripts/` directory and grant it execution permissions:
```bash
chmod +x <script_name>.sh
./<script_name>.sh
```
For example, to run the system info script:
```bash
chmod +x sys_info.sh
./sys_info.sh
```

## 🔒 Ethical Disclaimer

This toolkit is strictly for **educational, local system administration, and authorized testing purposes only**. Unauthorized use of these scripts against systems you do not have explicit permission to test is strictly prohibited. The author assumes no liability for misuse or damage caused by these tools.
