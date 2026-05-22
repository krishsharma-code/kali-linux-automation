#!/bin/bash

# file_backup.sh
# This script creates a backup of a file by appending '.bak' to its name.

# Check if the filename was provided.
if [ -z "$1" ]; then
    echo "Usage: ./file_backup.sh <filename>"
    exit 1
fi

FILE=$1

# Check if the file actually exists using the -f flag.
if [ -f "$FILE" ]; then
    # 'cp' stands for copy. We copy the original file to a new name.
    cp "$FILE" "${FILE}.bak"
    echo "Backup of '$FILE' created as '${FILE}.bak'."
else
    echo "Error: File '$FILE' not found."
    exit 1
fi
