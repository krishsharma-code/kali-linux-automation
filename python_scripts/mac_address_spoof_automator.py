#!/usr/bin/env python3
"""mac_address_spoof_automator.py

Day 12: System and Network Enumeration

Description:
    Automates changing a network interface's MAC address on Linux. The script
    brings the named interface down, assigns the new address, and brings the
    interface back up.

Cybersecurity Principle:
    MAC spoofing is used to maintain anonymity on a local network or to bypass
    MAC-based filtering / access-control lists (ACLs). It is a common red-team
    technique for blending in with authorized devices.

Safety:
    This is a state-changing tool. It requires root and momentarily interrupts
    the named interface. Pass ``--dry-run`` to print the commands it would run
    without touching the system. On any failure the interface is always brought
    back up before the script exits, so a failed run never leaves the host
    offline.

Exit codes:
    0 - the MAC address was changed (or a dry run completed)
    1 - the change failed, or an argument was rejected
    2 - argument parsing failed (argparse default)
"""

import argparse
import os
import random
import re
import shutil
import subprocess
import sys

# Linux interface names are at most IFNAMSIZ-1 (15) characters and, in practice,
# consist of letters, digits and a few punctuation characters. The first
# character must be alphanumeric so a fat-fingered or hostile argument such as
# "-x" cannot be interpreted as an option by `ip`.
_INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\Z")

# A MAC address is six colon-separated hex octets. The trailing \Z anchors the
# match so junk such as "aa:bb:cc:dd:ee:ff:zz" or "aa:bb:cc:dd:ee:ff00" is
# rejected rather than silently accepted by an unanchored re.match().
_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")

# Locally administered addresses set bit 1 of the first octet (0x02) and clear
# the multicast bit (0x01). A spoofed MAC should be locally administered so it
# cannot collide with a real, vendor-assigned address.
_LOCALLY_ADMINISTERED = 0x02
_MULTICAST = 0x01


def get_random_mac():
    """Return a random, valid, locally administered MAC address.

    The first octet has the locally-administered bit set and the multicast bit
    cleared; the remaining five octets are random.

    Returns:
        A lower-case MAC address such as ``"1a:2b:3c:4d:5e:6f"``.
    """
    first_octet = (random.randint(0x00, 0xFF) | _LOCALLY_ADMINISTERED) & ~_MULTICAST
    octets = [first_octet] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{octet:02x}" for octet in octets)


def is_valid_mac(value):
    """Return True when ``value`` is a syntactically valid MAC address.

    Args:
        value: Candidate MAC address string.

    Returns:
        True when the string is exactly six colon-separated hex octets.
    """
    return bool(_MAC_RE.fullmatch(value.lower()))


def is_valid_interface(interface):
    """Return True when ``interface`` looks like a safe Linux interface name."""
    return bool(_INTERFACE_RE.fullmatch(interface))


def change_mac(interface, new_mac, dry_run=False):
    """Point ``interface`` at ``new_mac``, restoring it to the up state on failure.

    Args:
        interface: Name of the network interface (for example ``eth0``).
        new_mac: MAC address to assign.
        dry_run: When True, print the commands without executing them.

    Returns:
        True when the address was set, False on failure.
    """
    commands = [
        ["ip", "link", "set", interface, "down"],
        ["ip", "link", "set", interface, "address", new_mac],
        ["ip", "link", "set", interface, "up"],
    ]

    if dry_run:
        print(f"[*] Dry run: would switch {interface} to {new_mac}")
        for command in commands:
            print(f"    {' '.join(command)}")
        return True

    print(f"[*] Switching {interface} to new MAC: {new_mac}")
    success = False
    try:
        subprocess.run(commands[0], check=True)
        subprocess.run(commands[1], check=True)
        success = True
    except subprocess.CalledProcessError as exc:
        print(f"[-] Error: Failed to change MAC address. "
              f"Ensure you have root privileges: {exc}")
    finally:
        # Never leave the interface down: whatever happened above, bring it back
        # up. This runs on the success path as well.
        try:
            subprocess.run(commands[2], check=True)
        except subprocess.CalledProcessError as exc:
            print(f"[!] Warning: could not bring {interface} back up: {exc}")

    if success:
        print(f"[+] Successfully changed MAC on {interface}")
    return success


def build_parser():
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Change a network interface's MAC address on Linux.")
    parser.add_argument(
        "interface",
        help="network interface to modify (for example eth0)")
    parser.add_argument(
        "new_mac", nargs="?", default=None,
        help="MAC address to assign (default: a random, locally administered one)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the commands that would run without changing anything")
    return parser


def main(argv=None):
    """Parse arguments, validate them and change the MAC address.

    Args:
        argv: Argument list to parse (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 on success, 1 on any failure.
    """
    args = build_parser().parse_args(argv)

    interface = args.interface
    new_mac = args.new_mac or get_random_mac()

    if not is_valid_interface(interface):
        print(f"[-] Error: Invalid interface name: {interface!r}")
        return 1

    if not is_valid_mac(new_mac):
        print(f"[-] Error: Invalid MAC address format: {new_mac!r}")
        return 1

    if not args.dry_run:
        if os.geteuid() != 0:
            print("[-] Error: Changing a MAC address requires root privileges.")
            return 1
        if shutil.which("ip") is None:
            print("[-] Error: the 'ip' command was not found in PATH.")
            return 1

    return 0 if change_mac(interface, new_mac, dry_run=args.dry_run) else 1


if __name__ == "__main__":
    sys.exit(main())
