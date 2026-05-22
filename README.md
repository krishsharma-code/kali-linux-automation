# Kali Linux Automation Toolkit

A collection of Python and Bash scripts designed for local system and network automation. This toolkit provides utilities for system information gathering, log management, and network analysis, tailored for efficiency in a Linux-style environment.

## 📌 Overview

This repository contains a suite of automation scripts that demonstrate core system administration and network diagnostic tasks. Whether you're managing local directories, monitoring logs, or analyzing network configurations, these scripts provide a solid foundation for automation in the terminal.

## 🛠️ Scripts Included

### 🐍 Python Scripts
- **01_create_system_directory.py**: Automates the creation of organized system directory structures.
- **02_write_sample_logs.py**: Generates sample log files for testing and monitoring practice.
- **03_run_basic_ping.py**: Performs a simple connectivity check against common targets (like Google DNS).
- **04_list_directory_contents.py**: A utility to systematically list and inspect directory structures.

### 🐚 Bash Scripts
- **local_net_analyzer.sh**: A powerful network diagnostic script that gathers IP information, routing tables, and active listening services into a consolidated report.

## 🚀 Usage

### Running Python Scripts
Ensure you have Python 3 installed. Run any Python script using:
```bash
python3 <script_name>.py
```

### Running the Bash Script
Before running the network analyzer, you must grant it execution permissions:
```bash
chmod +x local_net_analyzer.sh
./local_net_analyzer.sh
```
The script will generate a file named `local_net_report.txt` containing the analysis results.

## 🔒 Ethical Disclaimer

This toolkit is strictly for **educational, local system administration, and authorized testing purposes only**. Unauthorized use of these scripts against systems you do not have explicit permission to test is strictly prohibited. The author assumes no liability for misuse or damage caused by these tools.
