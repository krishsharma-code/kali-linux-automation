#!/usr/bin/env python3
"""
64_steganography_detector.py - Detects hidden data appended to image End-of-File markers.
Day 9: Forensics and Hardening
"""

import os

def detect_eof_data(file_path):
    """Detects data after the standard JPEG EOF marker (FF D9)."""
    if not file_path.lower().endswith(('.jpg', '.jpeg')):
        print(f"[SKIP] {file_path} is not a JPEG.")
        return

    with open(file_path, 'rb') as f:
        content = f.read()
        eof_marker = b'\xff\xd9'
        offset = content.find(eof_marker)
        
        if offset != -1 and offset < len(content) - 2:
            extra_data = content[offset + 2:]
            print(f"[ALERT] Hidden data found in {file_path}!")
            print(f"EOF Offset: {offset}")
            print(f"Hidden Bytes (first 20): {extra_data[:20].hex()}")
        else:
            print(f"[SAFE] No hidden EOF data detected in {file_path}.")

if __name__ == "__main__":
    print("--- Steganography EOF Detector ---")
    # Example usage (user would provide a real image path)
    detect_eof_data("sample_image.jpg")
