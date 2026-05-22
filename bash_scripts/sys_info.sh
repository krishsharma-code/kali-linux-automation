#!/bin/bash

# sys_info.sh
# This script fetches and prints basic system and kernel information.

echo "--- System Information ---"

# 'uname -s' prints the operating system name.
# 'uname -r' prints the kernel release version.
# 'uname -m' prints the machine hardware name.
echo "Operating System: $(uname -s)"
echo "Kernel Version: $(uname -r)"
echo "Hardware Architecture: $(uname -m)"

# 'hostname' displays the name of the machine.
echo "Hostname: $(hostname)"

echo "--------------------------"
