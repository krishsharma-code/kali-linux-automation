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
