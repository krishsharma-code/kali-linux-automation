#!/bin/bash
# 08_log_reader.sh
# Demonstrates reading specific parts of a file using cat, head, and tail.

# We'll use /etc/passwd as an example (standard system file)
TARGET_FILE="/etc/passwd"

echo "[*] Reading the first 5 lines of $TARGET_FILE:"
# 'head -n 5' shows the top 5 lines
head -n 5 $TARGET_FILE

echo -e "\n[*] Reading the last 5 lines of $TARGET_FILE:"
# 'tail -n 5' shows the bottom 5 lines
tail -n 5 $TARGET_FILE

echo -e "\n[*] Reading the entire file (first few lines shown via head for brevity):"
# 'cat' prints the whole file
cat $TARGET_FILE | head -n 10

echo -e "\n[+] Log reading demonstration complete."
