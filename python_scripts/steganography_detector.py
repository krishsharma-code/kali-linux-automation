#!/usr/bin/env python3
"""
steganography_detector.py - Detects hidden data appended to image End-of-File markers.

Day 9: Forensics and Hardening

Usage:
    python3 steganography_detector.py <image.jpg>
    python3 steganography_detector.py --help
"""

import argparse
import os
import sys


def detect_eof_data(file_path):
    """Detect data after the standard JPEG EOF marker (FF D9)."""
    if not file_path.lower().endswith(('.jpg', '.jpeg')):
        print(f"[SKIP] {file_path} is not a JPEG.")
        return

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
    except OSError as exc:
        print(f"[!] Could not read {file_path}: {exc}")
        return

    eof_marker = b'\xff\xd9'
    offset = content.find(eof_marker)

    if offset != -1 and offset < len(content) - 2:
        extra_data = content[offset + 2:]
        print(f"[ALERT] Hidden data found in {file_path}!")
        print(f"EOF Offset: {offset}")
        print(f"Hidden Bytes (first 20): {extra_data[:20].hex()}")
    else:
        print(f"[SAFE] No hidden EOF data detected in {file_path}.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="steganography_detector.py",
        description="Detect data hidden after a JPEG End-of-File (FF D9) marker.",
        epilog="Example: python3 steganography_detector.py photo.jpg",
    )
    parser.add_argument(
        "image",
        nargs="?",
        default=None,
        help="Path to the JPEG image to analyse",
    )
    args = parser.parse_args(argv)

    print("--- Steganography EOF Detector ---")

    if not args.image:
        print("[!] No image supplied.")
        print("    Usage: python3 steganography_detector.py <image.jpg>")
        return 0

    if not os.path.isfile(args.image):
        print(f"[!] File not found: {args.image}")
        print("    Provide a path to an existing JPEG image.")
        return 0

    detect_eof_data(args.image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
