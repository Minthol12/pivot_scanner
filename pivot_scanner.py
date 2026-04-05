#!/usr/bin/env python3
"""
Network Pivot Scanner – Phoenix404
Interactive CLI with validation for proxy, CIDR, ports, and threads.
"""

import sys
import socket
import argparse
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import socks

VERSION = "1.1"
DEFAULT_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443]

config = {
    "proxy_host": None,
    "proxy_port": None,
    "target_network": None,
    "ports": DEFAULT_PORTS.copy(),
    "threads": 50
}
results = {}

# ------------------------------------------------------------
# Validation functions
# ------------------------------------------------------------
def validate_cidr(cidr):
    """Check if CIDR is valid IPv4/IPv6 network"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_proxy(host, port, timeout=3):
    """Test if SOCKS5 proxy is responsive by attempting a connection to a known host (8.8.8.8:80)"""
    try:
        # Set up socks proxy temporarily
        test_sock = socks.socksocket()
        test_sock.set_proxy(socks.SOCKS5, host, port)
        test_sock.settimeout(timeout)
        # Try to connect to a reliable external IP (Google DNS)
        test_sock.connect(("8.8.8.8", 80))
        test_sock.close()
        return True
    except Exception as e:
        print(f"    Proxy test failed: {e}")
        return False

def validate_ports(ports):
    """Ensure ports are within 1-65535 and no duplicates"""
    if not ports:
        return False
    for p in ports:
        if not isinstance(p, int) or p < 1 or p > 65535:
            return False
    return len(ports) == len(set(ports))

def validate_threads(threads):
    return isinstance(threads, int) and 1 <= threads <= 500

# ------------------------------------------------------------
# Core scanning functions
# ------------------------------------------------------------
def setup_socks_proxy(proxy_host, proxy_port):
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
    socket.socket = socks.socksocket
    print(f"[+] SOCKS5 proxy configured: {proxy_host}:{proxy_port}")

def check_host_alive(ip, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 80))
        sock.close()
        return result == 0
    except:
        return False

def scan_port(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            banner = grab_banner(ip, port, timeout)
            return port, True, banner
        return port, False, None
    except:
        return port, False, None

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port == 22:
            sock.send(b"SSH-2.0-Client\r\n")
        elif port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
        else:
            sock.send(b"\r\n")
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100]
    except:
        return "banner unavailable"

def scan_network():
    global results
    # Validate everything before scan
    if not config["proxy_host"] or not config["proxy_port"]:
        print("[-] Proxy not configured. Use option 1.")
        return
    if not validate_proxy(config["proxy_host"], config["proxy_port"]):
        print("[-] Proxy unreachable or invalid. Check your proxy settings.")
        return
    if not config["target_network"]:
        print("[-] Target network not set. Use option 2.")
        return
    if not validate_cidr(config["target_network"]):
        print("[-] Invalid CIDR format. Use something like 10.0.0.0/24")
        return
    if not validate_ports(config["ports"]):
        print("[-] Invalid port list. Ports must be 1-65535, no duplicates.")
        return
    if not validate_threads(config["threads"]):
        print("[-] Thread count must be between 1 and 500.")
        return

    setup_socks_proxy(config["proxy_host"], config["proxy_port"])
    network = ipaddress.ip_network(config["target_network"], strict=False)
    hosts = list(network.hosts())
    print(f"[*] Scanning {len(hosts)} IPs in {config['target_network']} for {len(config['ports'])} ports each")

    alive_hosts = []
    print("[*] Checking for live hosts (TCP/80 echo)...")
    with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
        future_to_ip = {executor.submit(check_host_alive, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                alive_hosts.append(ip)
                print(f"[+] Host alive: {ip}")

    if not alive_hosts:
        print("[-] No live hosts found.")
        results = {}
        return

    print(f"\n[*] Scanning {len(alive_hosts)} live hosts for open ports...")
    results = {}
    for ip in alive_hosts:
        print(f"\n[*] Scanning {ip}")
        open_ports = []
        with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in config["ports"]}
            for future in as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))
                    print(f"    [+] Port {port} open - {banner}")
        results[ip] = open_ports

    print("\n[+] Scan complete.")
    show_summary()

def show_summary():
    global results
    if not results:
        print("[-] No scan results available. Run scan first (option 4).")
        return
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    for ip, ports_list in results.items():
        if ports_list:
            print(f"\n{ip}:")
            for port, banner in ports_list:
                print(f"  {port} -> {banner}")
        else:
            print(f"\n{ip}: no open ports found")
    print("\n" + "="*60)
    print("LATERAL MOVEMENT SUGGESTIONS")
    print("="*60)
    for ip, ports_list in results.items():
        for port, _ in ports_list:
            if port == 22:
                print(f"  SSH on {ip} → try: ssh user@{ip} (credential reuse)")
            elif port == 445:
                print(f"  SMB on {ip} → try: smbclient or psexec")
            elif port == 3389:
                print(f"  RDP on {ip} → try: xfreerdp /v:{ip}")
            elif port == 5900:
                print(f"  VNC on {ip} → try: vncviewer {ip}")
            elif port == 80 or port == 443 or port == 8080:
                print(f"  Web on {ip}:{port} → check for vulns (dirb, nikto)")

def export_results():
    if not results:
        print("[-] No results to export. Run scan first.")
        return
    filename = input("Export filename (default: scan_results.json): ").strip()
    if not filename:
        filename = "scan_results.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results exported to {filename}")

def set_proxy():
    proxy = input("Enter SOCKS5 proxy (host:port) [e.g., 127.0.0.1:1080]: ").strip()
    try:
        host, port = proxy.split(":")
        port = int(port)
        if port < 1 or port > 65535:
            print("[-] Port out of range (1-65535)")
            return
        # Test proxy immediately
        print("[*] Testing proxy connection...")
        if validate_proxy(host, port):
            config["proxy_host"] = host
            config["proxy_port"] = port
            print(f"[+] Proxy set and verified: {host}:{port}")
        else:
            print("[-] Proxy test failed. Settings not saved.")
    except ValueError:
        print("[-] Invalid format. Use host:port")

def set_target():
    target = input("Enter target network CIDR [e.g., 10.0.0.0/24]: ").strip()
    if validate_cidr(target):
        config["target_network"] = target
        print(f"[+] Target network set to {target}")
        # Show number of IPs
        network = ipaddress.ip_network(target, strict=False)
        print(f"    This network contains {network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses} usable hosts")
    else:
        print("[-] Invalid CIDR format. Example: 192.168.1.0/24")

def set_ports():
    ports_input = input(f"Enter ports (comma-separated, or 'default' for {DEFAULT_PORTS}): ").strip()
    if ports_input.lower() == 'default':
        config["ports"] = DEFAULT_PORTS.copy()
        print(f"[+] Ports set to default: {config['ports']}")
        return
    try:
        ports = [int(p.strip()) for p in ports_input.split(",")]
        if validate_ports(ports):
            config["ports"] = ports
            print(f"[+] Ports set: {config['ports']}")
        else:
            print("[-] Invalid port list. Ports must be 1-65535, no duplicates.")
    except ValueError:
        print("[-] Invalid input. Use numbers separated by commas.")

def set_threads():
    try:
        t = int(input(f"Max threads (current {config['threads']}, 1-500): ").strip())
        if validate_threads(t):
            config["threads"] = t
            print(f"[+] Threads set to {t}")
        else:
            print("[-] Thread count must be between 1 and 500.")
    except ValueError:
        print("[-] Invalid number.")

def show_config():
    print("\nCurrent Configuration:")
    print(f"  Proxy: {config['proxy_host']}:{config['proxy_port'] if config['proxy_port'] else 'Not set'}")
    print(f"  Target network: {config['target_network'] or 'Not set'}")
    print(f"  Ports: {config['ports']}")
    print(f"  Threads: {config['threads']}")

def pre_scan_check():
    """Run all validations without scanning"""
    print("\n=== PRE-SCAN VALIDATION ===\n")
    errors = []
    if not config["proxy_host"] or not config["proxy_port"]:
        errors.append("Proxy not set")
    else:
        print(f"[*] Testing proxy {config['proxy_host']}:{config['proxy_port']}...")
        if validate_proxy(config["proxy_host"], config["proxy_port"]):
            print("[+] Proxy reachable")
        else:
            errors.append("Proxy unreachable")
    if not config["target_network"]:
        errors.append("Target network not set")
    else:
        if validate_cidr(config["target_network"]):
            print(f"[+] CIDR valid: {config['target_network']}")
        else:
            errors.append("Invalid CIDR")
    if not validate_ports(config["ports"]):
        errors.append("Invalid ports list")
    else:
        print(f"[+] Ports valid: {config['ports']}")
    if not validate_threads(config["threads"]):
        errors.append("Invalid thread count")
    else:
        print(f"[+] Thread count valid: {config['threads']}")
    if errors:
        print("\n[-] Validation failed:")
        for e in errors:
            print(f"    - {e}")
        return False
    else:
        print("\n[+] All settings are valid. Ready to scan.")
        return True

def interactive_menu():
    while True:
        print("\n" + "="*50)
        print("  NETWORK PIVOT SCANNER - Phoenix404")
        print("="*50)
        print("1. Set SOCKS5 proxy (with test)")
        print("2. Set target network (CIDR)")
        print("3. Set ports to scan")
        print("4. Set thread count")
        print("5. Show current config")
        print("6. Pre-scan validation check")
        print("7. RUN SCAN")
        print("8. Show scan summary")
        print("9. Export results (JSON)")
        print("10. Exit")
        choice = input("\nChoice: ").strip()
        if choice == '1':
            set_proxy()
        elif choice == '2':
            set_target()
        elif choice == '3':
            set_ports()
        elif choice == '4':
            set_threads()
        elif choice == '5':
            show_config()
        elif choice == '6':
            pre_scan_check()
        elif choice == '7':
            scan_network()
        elif choice == '8':
            show_summary()
        elif choice == '9':
            export_results()
        elif choice == '10':
            print("[+] Exiting.")
            sys.exit(0)
        else:
            print("[-] Invalid choice")

def main():
    parser = argparse.ArgumentParser(description="Network Pivot Scanner")
    parser.add_argument("--proxy", help="SOCKS5 proxy (host:port)")
    parser.add_argument("--target", help="Target CIDR")
    parser.add_argument("--ports", help="Comma-separated ports")
    parser.add_argument("--threads", type=int, default=50)
    args = parser.parse_args()

    if args.proxy or args.target or args.ports:
        # Non-interactive mode with minimal validation
        if not args.proxy or not args.target:
            print("[-] Both --proxy and --target required in command-line mode.")
            sys.exit(1)
        try:
            host, port = args.proxy.split(":")
            config["proxy_host"] = host
            config["proxy_port"] = int(port)
        except:
            print("[-] Invalid proxy format. Use host:port")
            sys.exit(1)
        if not validate_cidr(args.target):
            print("[-] Invalid CIDR")
            sys.exit(1)
        config["target_network"] = args.target
        if args.ports:
            ports = [int(p) for p in args.ports.split(",")]
            if validate_ports(ports):
                config["ports"] = ports
            else:
                print("[-] Invalid ports list")
                sys.exit(1)
        if args.threads:
            if validate_threads(args.threads):
                config["threads"] = args.threads
            else:
                print("[-] Threads must be 1-500")
                sys.exit(1)
        scan_network()
        show_summary()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()