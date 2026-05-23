#!/bin/bash
# 01_file_permissions.sh
# Demonstrates creating a dummy file and changing its permissions.

# Create a dummy script file
echo "echo 'Hello from dummy script!'" > dummy_script.sh
echo "[+] Created dummy_script.sh"

# Show current permissions
echo "[*] Current permissions:"
ls -l dummy_script.sh

# Change permissions to make it executable
# 'chmod +x' adds execution rights for the owner, group, and others
chmod +x dummy_script.sh
echo "[+] Permissions updated with chmod +x"

# Show updated permissions
echo "[*] Updated permissions:"
ls -l dummy_script.sh

# Clean up (optional, but good practice in learning scripts)
# rm dummy_script.sh
