#!/bin/bash

# disk_monitor.sh
# This script displays the available disk space using the 'df' command.

echo "--- Disk Space Usage ---"

# 'df' reports file system disk space usage.
# '-h' flag makes the output human-readable (KB, MB, GB).
df -h

echo "------------------------"
