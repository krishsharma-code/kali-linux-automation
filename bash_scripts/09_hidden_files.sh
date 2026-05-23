#!/bin/bash
# 09_hidden_files.sh
# Demonstrates creating and viewing hidden files in Linux.

# In Linux, any file or directory starting with a dot (.) is hidden
HIDDEN_FILE=".hidden_note.txt"

echo "This is a secret note." > $HIDDEN_FILE
echo "[+] Created a hidden file: $HIDDEN_FILE"

echo "[*] Standard 'ls' output (hidden files not shown):"
ls

echo -e "\n[*] 'ls -la' output (hidden files are visible):"
# '-l' uses long listing format, '-a' shows all files (including hidden)
ls -la | grep $HIDDEN_FILE

# Clean up
rm $HIDDEN_FILE
echo "[+] Removed hidden file."
