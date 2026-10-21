#!/bin/bash

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root" 
   exit 1
fi

echo "[*] Disabling USB Storage Autorun/Automount..."

# 1. Disable automount via dconf (for GNOME/Desktop environments)
if command -v dconf &> /dev/null; then
    echo "[*] Disabling GNOME automount..."
    dconf write /org/gnome/desktop/media-handling/automount false
    dconf write /org/gnome/desktop/media-handling/automount-open false
fi

# 2. Block 'usb-storage' module if strict lockdown is needed
# echo "blacklist usb-storage" > /etc/modprobe.d/usb-storage.conf
# modprobe -r usb-storage

# 3. Secure udev rules (example: mount with noexec)
RULE_FILE="/etc/udev/rules.d/99-block-usb-autorun.rules"
echo "[*] Creating restrictive udev rule at $RULE_FILE..."
cat <<EOF > "$RULE_FILE"
# Secure USB mounting: mount with noexec, nosuid, nodev
SUBSYSTEM=="usb", ACTION=="add", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec,nosuid,nodev"
EOF

# Reload udev
udevadm control --reload-rules
udevadm trigger

echo "[+] USB Autorun/Execution protection applied."
