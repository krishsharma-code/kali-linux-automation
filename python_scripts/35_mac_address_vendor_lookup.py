import requests

def lookup_mac(mac_address):
    """
    Looks up the MAC address vendor using the macvendors.com API.
    """
    print(f"[*] Looking up vendor for MAC: {mac_address}")
    url = f"https://api.macvendors.com/{mac_address}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Vendor Not Found"
    except Exception as e:
        return f"Request Error: {e}"

if __name__ == "__main__":
    # Example MAC (Google Inc)
    test_mac = "3C:5A:B4:00:00:00"
    vendor = lookup_mac(test_mac)
    print(f"[+] Vendor: {vendor}")
