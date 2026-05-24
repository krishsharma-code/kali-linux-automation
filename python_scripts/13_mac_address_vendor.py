#!/usr/bin/env python3

# 13_mac_address_vendor.py
# Concept: Mocking an API lookup for MAC address OUI (Organizationally Unique Identifier)

def lookup_vendor(mac_address):
    # This is a mock database of MAC prefixes (OUIs)
    vendor_db = {
        "00:0C:29": "VMware, Inc.",
        "08:00:27": "Oracle (VirtualBox)",
        "B8:27:EB": "Raspberry Pi Foundation",
        "00:15:5D": "Microsoft (Hyper-V)",
        "00:1A:11": "Google, Inc."
    }
    
    # Clean the input and get the first 8 characters (OUI)
    prefix = mac_address.upper()[:8].replace("-", ":")
    
    return vendor_db.get(prefix, "Unknown Vendor")

if __name__ == "__main__":
    print("--- MAC Vendor Lookup (Mock) ---")
    test_mac = input("Enter MAC Address (e.g., 08:00:27:xx:xx:xx): ") or "08:00:27:AA:BB:CC"
    vendor = lookup_vendor(test_mac)
    print(f"[*] MAC: {test_mac}")
    print(f"[+] Vendor: {vendor}")
