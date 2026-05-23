#!/bin/bash
# 04_file_ops.sh
# Automates basic file operations: touch, cp, mv, and rm.

# 1. Create a file using 'touch'
touch test_file.txt
echo "[+] Created test_file.txt"

# 2. Copy the file using 'cp'
cp test_file.txt test_file_copy.txt
echo "[+] Copied file to test_file_copy.txt"

# 3. Move/Rename the file using 'mv'
mv test_file_copy.txt renamed_file.txt
echo "[+] Renamed copy to renamed_file.txt"

# 4. Remove files using 'rm'
rm test_file.txt renamed_file.txt
echo "[+] Cleaned up: removed test_file.txt and renamed_file.txt"
