#!/bin/bash

# Define CPU threshold (e.g., 20%)
THRESHOLD=20.0

echo "[*] Scanning for high-CPU processes without a TTY..."
echo "----------------------------------------------------"

# Get processes using more than THRESHOLD% CPU and having no TTY (?)
# ps -eo pid,ppid,user,%cpu,tty,comm --sort=-%cpu
ps -eo pid,user,%cpu,tty,comm --sort=-%cpu | awk -v thresh="$THRESHOLD" '$3 > thresh && $4 == "?" {print $1, $2, $3, $5}' | while read pid user cpu comm; do
    echo "[!] Found Rogue Candidate: PID=$pid | User=$user | CPU=$cpu% | Cmd=$comm"
    read -p "    Terminate this process? (y/N): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        kill -9 $pid
        echo "    [+] PID $pid killed."
    else
        echo "    [ ] Skipped."
    fi
done

echo "----------------------------------------------------"
echo "[*] Scan complete."
