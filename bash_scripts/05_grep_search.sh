#!/bin/bash
# 05_grep_search.sh
# Demonstrates searching for specific patterns inside a log file.

# Create a sample log file
cat <<EOF > system.log
[INFO] System started.
[INFO] User 'admin' logged in.
[ERROR] Database connection failed!
[INFO] Retrying connection...
[DEBUG] Checking credentials.
[ERROR] Unauthorized access attempt detected.
[INFO] System shutting down.
EOF

echo "[+] Sample log file 'system.log' created."

# Use 'grep' to search for 'ERROR'
echo "[*] Searching for ERRORS in log:"
grep "ERROR" system.log

# Search for multiple keywords using -E (extended regex)
echo "[*] Searching for INFO or DEBUG messages:"
grep -E "INFO|DEBUG" system.log

# Clean up
rm system.log
