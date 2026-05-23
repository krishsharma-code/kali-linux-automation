#!/bin/bash
# 07_user_recon.sh
# Gathers information about the current user and active sessions.

echo "[*] Current User Identification:"

# 'whoami' prints the effective username
echo "Username: $(whoami)"

# 'id' prints real and effective user and group IDs
echo "User & Group IDs: $(id)"

# 'w' shows who is logged on and what they are doing
echo -e "\n[*] Active Sessions:"
w

echo -e "\n[+] User reconnaissance finished."
