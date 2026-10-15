import sys
import re

ip_pattern = re.compile(r"Nmap scan report for (.+)")
port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)")

scan_results = {}
current_ip = None

for line in sys.stdin:
    clean_line = line.strip()
    
    ip_match = ip_pattern.search(clean_line)

    if ip_match:
        current_ip = ip_match.group(1)
        scan_results[current_ip] = []
        continue


    if current_ip:
        port_match = port_pattern.match(clean_line)
        if port_match:
            port = port_match.group(1)
            protocol = port_match.group(2)
            service = port_match.group(3)
            version = port_match.group(4) or "Unknown"

            scan_results[current_ip].append({
                "port": f"{port}/{protocol}",
                "service": f"{service}",
                "version": f"{version}" 
            })

print("\n" + "="*50)
print("               Scanning Results           ")
print("="*50)

for ip, ports in scan_results.items():
    print(f"\n TARGET: {ip}")
    print("-" * 50)
    #
    print(f"{'PORT':<12} {'SERVICE':<15} {'VERSION'}")
    print("-" * 50)
    
    if not ports:
        print("No open ports.")
    else:
        for p in ports:
            print(f"{p['port']:<12} {p['service']:<15} {p['version']}")
    print("-" * 50)

