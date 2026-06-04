import dns.resolver
import dns.query
import dns.zone
import argparse
import sys

def check_zone_transfer(domain):
    """Attempts a DNS zone transfer for a given domain."""
    print(f"[*] Checking zone transfer for domain: {domain}")
    
    try:
        # Find the Name Servers for the domain
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_servers = [str(ns.target) for ns in ns_records]
        
        if not ns_servers:
            print("[!] No Name Servers found.")
            return

        print(f"[*] Found {len(ns_servers)} Name Servers: {', '.join(ns_servers)}")

        for server in ns_servers:
            print(f"[*] Attempting zone transfer from {server}...")
            try:
                # Attempt the transfer
                zone = dns.zone.from_xfr(dns.query.xfr(server, domain))
                if zone:
                    print(f"[!] SUCCESS: Zone transfer successful from {server}!")
                    for name, node in zone.nodes.items():
                        print(f"    {name}.{domain} -> {node.to_text(name)}")
                else:
                    print(f"[-] Failed: No data returned from {server}")
            except Exception as e:
                print(f"[-] Failed: {server} refused transfer or error occurred.")
                
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="DNS Zone Transfer Checker")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    args = parser.parse_args()

    # Note: Requires dnspython library
    try:
        import dns
    except ImportError:
        print("[!] Error: 'dnspython' library not found. Install it with: pip install dnspython")
        sys.exit(1)

    check_zone_transfer(args.domain)

if __name__ == "__main__":
    main()
