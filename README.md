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
- **31_ping_sweeper.py**: (Day 6 Network Reconnaissance) Uses subprocess to find live hosts in a /24 subnet.
- **32_basic_port_scanner.py**: (Day 6 Network Reconnaissance) Socket-based TCP scanner for common ports.
- **33_banner_grabber.py**: (Day 6 Network Reconnaissance) Connects to ports to retrieve service banners.
- **34_nmap_xml_parser.py**: (Day 6 Network Reconnaissance) Extracts open ports and services from Nmap XML output.
- **35_mac_address_vendor_lookup.py**: (Day 6 Network Reconnaissance) Looks up device vendors using MAC address APIs.
- **41_auth_log_parser.py**: (Day 7 Defensive Monitoring) Parses a mock auth.log to count failed SSH login attempts.
- **42_file_integrity_monitor.py**: (Day 7 Defensive Monitoring) Generates SHA-256 hashes of critical files and alerts on changes.
- **43_malicious_ip_blocker.py**: (Day 7 Defensive Monitoring) Reads bad IPs and generates UFW block commands.
- **44_suspicious_process_hunter.py**: (Day 7 Defensive Monitoring) Finds processes running from unusual directories like /tmp.
- **45_yara_rule_generator.py**: (Day 7 Defensive Monitoring) Generates basic YARA rule syntax for signature matching.
- **51_http_header_analyzer.py**: (Day 8 Web Recon) Fetches HTTP headers using the 'requests' library to find server versions.
- **52_robots_txt_scraper.py**: (Day 8 Web Recon) Downloads and parses a site's robots.txt to find hidden directories.
- **53_subdomain_bruteforcer_mock.py**: (Day 8 Web Recon) Reads a wordlist and tests common subdomains against a target domain.
- **54_ssl_cert_checker.py**: (Day 8 Web Recon) Uses 'ssl' and 'socket' libraries to pull and read an SSL/TLS certificate's expiration date.
- **55_directory_fuzzer_lite.py**: (Day 8 Web Recon) Lightweight script that checks for common admin/login paths returning 200 OK statuses.
- **61_ssh_log_analyzer.py**: (Day 9 Forensics and Hardening) Parses a mock auth.log file to extract IP addresses with multiple failed SSH login attempts.
- **62_malware_hash_checker.py**: (Day 9 Forensics and Hardening) Calculates SHA-256 hashes of files in a directory and compares them against a known mock signature list.
- **63_packet_sniffer_scapy_basic.py**: (Day 9 Forensics and Hardening) A basic script using Scapy to capture and print summary details of local network packets.
- **64_steganography_detector.py**: (Day 9 Forensics and Hardening) Analyzes image file structures to detect hidden data appended to the End-of-File marker.
- **65_termux_environment_checker.py**: (Day 9 Forensics and Hardening) Validates missing packages, network tools, and file paths specific to a Termux mobile environment.
- **71_cve_database_lookup.py**: (Day 10 Vulnerability Scanning) Queries a mock local JSON database for CVE details based on user input.
- **72_port_scanner_banner_grab.py**: (Day 10 Vulnerability Scanning) A multi-threaded socket script to scan ports and grab service banners.
- **73_subdomain_takeover_check.py**: (Day 10 Vulnerability Scanning) Checks a list of subdomains for common CNAME dangling errors.
- **74_pdf_vuln_report_gen.py**: (Day 10 Vulnerability Scanning) Uses a lightweight mock logic to format scan results into a readable text/PDF structure.
- **75_api_endpoint_fuzzer.py**: (Day 10 Vulnerability Scanning) Fuzzes a mock target URL with common API paths looking for 200 OK responses.
- **81_passwd_file_analyzer.py**: (Day 11 Local Enumeration) Reads /etc/passwd and extracts users with interactive shell access.
- **82_cron_job_parser.py**: (Day 11 Local Enumeration) Simulates parsing crontab files to identify potentially vulnerable scheduled tasks.
- **83_log_file_monitor.py**: (Day 11 Local Enumeration) A script that tails a mock auth.log file and alerts on failed SSH logins.
- **84_file_hash_checker.py**: (Day 11 Local Enumeration) Calculates SHA-256 hashes of critical system binaries to check for tampering.
- **85_network_interface_auditor.py**: (Day 11 Local Enumeration) Uses the os and subprocess modules to list active interfaces and check promiscuous mode.
- **91_subnet_mask_parser.py**: (Day 12 System and Network Enumeration) Parses CIDR notation and calculates network range and host limits.
- **92_live_host_ping_sweep.py**: (Day 12 System and Network Enumeration) Threaded ICMP sweep to discover active network nodes.
- **93_mac_address_spoof_automator.py**: (Day 12 System and Network Enumeration) Safely rotates hardware MAC addresses for anonymity.
- **94_dns_recon_resolver.py**: (Day 12 System and Network Enumeration) Resolves standard DNS records (A, MX, TXT) for target mapping.
- **95_socket_banner_grabber.py**: (Day 12 System and Network Enumeration) Fingerprints service versions using low-level socket connections.

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
- **36_quick_nmap_scan.sh**: (Day 6 Network Reconnaissance) Fast scan of the top 100 common ports.
- **37_full_tcp_syn_scan.sh**: (Day 6 Network Reconnaissance) Stealthy SYN scan of all 65535 ports.
- **38_dns_enum_script.sh**: (Day 6 Network Reconnaissance) Forward and reverse DNS lookup automation.
- **39_arp_discovery.sh**: (Day 6 Network Reconnaissance) Identifies local devices using ARP requests.
- **40_ssl_cert_checker.sh**: (Day 6 Network Reconnaissance) Checks SSL certificate expiration and details.
- **46_active_connections_monitor.sh**: (Day 7 Defensive Monitoring) Lists established connections and their PIDs using netstat/ss.
- **47_suid_guid_finder.sh**: (Day 7 Defensive Monitoring) Finds files with SUID/GUID bits set to audit priv-esc risks.
- **48_firewall_status_check.sh**: (Day 7 Defensive Monitoring) Checks UFW/iptables status and dumps rules to a log.
- **49_cronjob_auditor.sh**: (Day 7 Defensive Monitoring) Lists all scheduled cron jobs to check for persistence.
- **50_system_baseline_snapshot.sh**: (Day 7 Defensive Monitoring) Takes a snapshot of installed packages and services.
- **56_nmap_quick_scan_wrapper.sh**: (Day 8 Enumeration) Automates an Nmap fast scan and outputs clean results to a file.
- **57_dns_enum_tool.sh**: (Day 8 Enumeration) Uses 'host' and 'dig' to extract DNS records like A, MX, and TXT.
- **58_whois_ip_lookup.sh**: (Day 8 Enumeration) Takes a list of IPs and runs 'whois' to extract organizational data.
- **59_ping_sweep_subnet.sh**: (Day 8 Enumeration) Simple bash loop to ping all hosts in a /24 subnet to find live machines.
- **60_banner_grabber_netcat.sh**: (Day 8 Enumeration) Automates 'nc' to connect to a specific port and grab service banners.
- **66_kali_usb_persistence_check.sh**: (Day 9 Forensics and Hardening) A script to verify the partition health and mounting status of a 256GB persistent Kali Linux flash drive.
- **67_active_connections_monitor.sh**: (Day 9 Forensics and Hardening) Wraps ss or netstat to continuously log suspicious outbound connections.
- **68_file_integrity_monitor.sh**: (Day 9 Forensics and Hardening) A script designed for a cron job that checks the hashes of critical system files and alerts on changes.
- **69_firewall_iptables_setup.sh**: (Day 9 Forensics and Hardening) Automates the configuration of basic defensive iptables rules to drop inbound traffic while allowing established connections.
- **70_suspicious_process_hunter.sh**: (Day 9 Forensics and Hardening) Scans running processes to identify unusually high resource usage or suspicious execution paths.
- **76_nmap_vuln_automator.sh**: (Day 10 Vulnerability Scanning) Wraps Nmap with the --script vuln flag and formats the output.
- **77_nikto_web_scanner_wrapper.sh**: (Day 10 Vulnerability Scanning) Automates Nikto scans against a target and saves output to a timestamped file.
- **78_wp_scan_updater.sh**: (Day 10 Vulnerability Scanning) A script that safely updates WPScan databases and runs a basic enumeration scan.
- **79_ssh_audit_tool.sh**: (Day 10 Vulnerability Scanning) Checks local SSH configuration files for weak ciphers and root login permissions.
- **80_daily_security_summary.sh**: (Day 10 Vulnerability Scanning) Compiles logs from previous scripts and outputs a daily executive summary.
- **86_suid_binary_finder.sh**: (Day 11 Local Enumeration) Finds all files on the system with the SUID bit set and saves the list.
- **87_open_ports_enumerator.sh**: (Day 11 Local Enumeration) Uses ss or netstat to list all listening ports and the associated PIDs.
- **88_sudo_privilege_checker.sh**: (Day 11 Local Enumeration) Automates running sudo -l and parsing the output for NOPASSWD entries.
- **89_system_info_gatherer.sh**: (Day 11 Local Enumeration) Collects kernel version, hostname, and OS release info into a single recon file.
- **90_clear_logs_simulator.sh**: (Day 11 Local Enumeration) A script that demonstrates how threat actors clear bash history and wtmp logs, strictly for defensive understanding.
- **96_active_connections_monitor.sh**: (Day 12 System and Network Enumeration) Alerts on new unauthorized established TCP connections.
- **97_iptables_firewall_reset.sh**: (Day 12 System and Network Enumeration) Resets firewall rules to a secure default-deny posture.
- **98_arp_cache_poison_detector.sh**: (Day 12 System and Network Enumeration) Detects duplicate MAC addresses in ARP table to warn of spoofing.
- **99_wireless_interface_auditor.sh**: (Day 12 System and Network Enumeration) Evaluates wireless card modes and monitor capabilities.
- **100_network_recon_bundle.sh**: (Day 12 System and Network Enumeration) Aggregates interface, routing, and DNS data into a forensic dump.

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
ility for misuse or damage caused by these tools.
