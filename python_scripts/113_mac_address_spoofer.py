import subprocess
import random
import re
import argparse
import sys

def get_random_mac():
    """Generates a random MAC address."""
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def change_mac(interface, new_mac):
    """Changes the MAC address of a given interface."""
    print(f"[*] Changing MAC address for {interface} to {new_mac}")
    
    try:
        subprocess.call(["ifconfig", interface, "down"])
        subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["ifconfig", interface, "up"])
        print(f"[+] Successfully changed MAC address for {interface}")
    except Exception as e:
        print(f"[!] Error: {e}")

def get_current_mac(interface):
    """Retrieves the current MAC address of an interface."""
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode()
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if mac_address_search_result:
            return mac_address_search_result.group(0)
    except:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="MAC Address Spoofer")
    parser.add_argument("interface", help="Interface to change MAC for (e.g., eth0, wlan0)")
    parser.add_argument("--mac", help="New MAC address (random if not specified)")
    args = parser.parse_args()

    interface = args.interface
    new_mac = args.mac if args.mac else get_random_mac()

    current_mac = get_current_mac(interface)
    if not current_mac:
        print(f"[!] Could not find interface {interface}")
        sys.exit(1)

    print(f"[*] Current MAC: {current_mac}")
    change_mac(interface, new_mac)
    
    final_mac = get_current_mac(interface)
    if final_mac == new_mac:
        print(f"[+] MAC address changed successfully to {final_mac}")
    else:
        print(f"[!] Failed to change MAC address.")

if __name__ == "__main__":
    main()
