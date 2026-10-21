#!/usr/bin/env python3
"""
ping_sweeper.py - Pings a /24 subnet to find live hosts.

Day 6: Network Reconnaissance

Usage:
    python3 ping_sweeper.py [SUBNET_PREFIX]
    python3 ping_sweeper.py 192.168.1
    python3 ping_sweeper.py --help
"""

import argparse
import shutil
import subprocess
import sys


def ping_sweep(network_prefix):
    """Ping every host in <network_prefix>.0/24 and return the live ones.

    ``network_prefix`` is the first three octets, e.g. ``"192.168.1"``.
    """
    print(f"[*] Starting ping sweep on {network_prefix}.0/24...")
    live_hosts = []

    # Loop through 1 to 254
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        try:
            # -c 1 (1 packet), -W 1 (1 second timeout)
            response = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            # Defensive: the binary existed at startup but disappeared mid-run.
            print("[!] 'ping' became unavailable - aborting the sweep.")
            break

        if response.returncode == 0:
            print(f"[+] Host {ip} is UP")
            live_hosts.append(ip)

    return live_hosts


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ping_sweeper.py",
        description="Ping-sweep a /24 subnet to discover live hosts.",
        epilog="Example: python3 ping_sweeper.py 192.168.1",
    )
    parser.add_argument(
        "subnet",
        nargs="?",
        default="127.0.0",
        help="First three octets of the target subnet (default: 127.0.0)",
    )
    args = parser.parse_args(argv)

    # Graceful handling when the ping binary is not installed.
    if shutil.which("ping") is None:
        print("[!] 'ping' binary not found on this system.")
        print("    Install it (e.g. 'sudo apt install iputils-ping') and try again.")
        return 0

    live_hosts = ping_sweep(args.subnet)
    print(f"[+] Sweep complete. {len(live_hosts)} live host(s) found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
