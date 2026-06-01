#!/usr/bin/env python3
"""
84_file_hash_checker.py
Day 11: Local Enumeration
Description: Calculates SHA-256 hashes of critical system binaries to check for tampering.
"""

import hashlib
import os

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "NOT_FOUND"
    except Exception as e:
        return f"ERROR: {e}"

def audit_binaries():
    # Critical binaries to monitor
    binaries = [
        "/bin/bash",
        "/bin/ls",
        "/bin/ps",
        "/bin/netstat",
        "/usr/bin/sudo"
    ]
    
    print("[*] Auditing System Binaries (SHA-256 Hashes)...")
    print("-" * 65)
    print(f"{'Binary Path':<20} {'SHA-256 Hash'}")
    print("-" * 65)

    for binary in binaries:
        file_hash = get_file_hash(binary)
        print(f"{binary:<20} {file_hash}")

    print("-" * 65)
    print("[!] Note: Compare these hashes against a known good baseline for integrity verification.")

if __name__ == "__main__":
    audit_binaries()
