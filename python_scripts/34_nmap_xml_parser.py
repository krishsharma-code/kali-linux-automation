import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    """
    Parses Nmap XML output to extract open ports and services.
    """
    print(f"[*] Parsing Nmap XML: {file_path}")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            print(f"\nHost: {ip}")
            
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    state = port.find('state').get('state')
                    service = port.find('service').get('name') if port.find('service') is not None else "Unknown"
                    
                    if state == "open":
                        print(f"  - Port {port_id}/tcp: {service} ({state})")
    except FileNotFoundError:
        print("[-] XML file not found.")
    except Exception as e:
        print(f"[-] Error parsing XML: {e}")

if __name__ == "__main__":
    # This expects an 'output.xml' from 'nmap -oX output.xml <target>'
    parse_nmap_xml("output.xml")
