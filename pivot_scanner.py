#!/usr/bin/env python3
"""
Network Pivot Scanner – Phoenix404
Interactive CLI + command-line mode.
Scans internal networks via SOCKS5 proxy for lateral movement.

Usage:
    # Interactive mode (no args)
    python pivot_scanner.py

    # Command-line mode (non-interactive)
    python pivot_scanner.py --proxy 127.0.0.1:1080 --target 10.0.0.0/24 --ports 22,445,3389
"""

import sys
import socket
import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import socks
import ipaddress

VERSION = "1.0"
DEFAULT_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443]

# Global config
config = {
    "proxy_host": None,
    "proxy_port": None,
    "target_network": None,
    "ports": DEFAULT_PORTS.copy(),
    "threads": 50
}
results = {}

# ------------------------------------------------------------
# Core scanning functions (same as before)
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
    if not config["proxy_host"] or not config["proxy_port"]:
        print("[-] Proxy not configured. Use option 1 to set proxy.")
        return
    if not config["target_network"]:
        print("[-] Target network not set. Use option 2 to set target.")
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
        config["proxy_host"] = host
        config["proxy_port"] = int(port)
        print(f"[+] Proxy set to {host}:{port}")
    except:
        print("[-] Invalid format. Use host:port")

def set_target():
    target = input("Enter target network CIDR [e.g., 10.0.0.0/24]: ").strip()
    try:
        ipaddress.ip_network(target, strict=False)
        config["target_network"] = target
        print(f"[+] Target network set to {target}")
    except:
        print("[-] Invalid CIDR")

def set_ports():
    ports_input = input(f"Enter ports (comma-separated, or 'default' for {DEFAULT_PORTS}): ").strip()
    if ports_input.lower() == 'default':
        config["ports"] = DEFAULT_PORTS.copy()
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
            config["ports"] = ports
        except:
            print("[-] Invalid port list. Keeping previous.")
            return
    print(f"[+] Ports set: {config['ports']}")

def set_threads():
    try:
        t = int(input(f"Max threads (current {config['threads']}): ").strip())
        if t > 0:
            config["threads"] = t
            print(f"[+] Threads set to {t}")
        else:
            print("[-] Must be >0")
    except:
        print("[-] Invalid number")

def show_config():
    print("\nCurrent Configuration:")
    print(f"  Proxy: {config['proxy_host']}:{config['proxy_port'] if config['proxy_port'] else 'Not set'}")
    print(f"  Target network: {config['target_network'] or 'Not set'}")
    print(f"  Ports: {config['ports']}")
    print(f"  Threads: {config['threads']}")

def interactive_menu():
    while True:
        print("\n" + "="*50)
        print("  NETWORK PIVOT SCANNER - Phoenix404")
        print("="*50)
        print("1. Set SOCKS5 proxy")
        print("2. Set target network (CIDR)")
        print("3. Set ports to scan")
        print("4. Set thread count")
        print("5. Show current config")
        print("6. RUN SCAN")
        print("7. Show scan summary")
        print("8. Export results (JSON)")
        print("9. Exit")
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
            scan_network()
        elif choice == '7':
            show_summary()
        elif choice == '8':
            export_results()
        elif choice == '9':
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

    # If any CLI args provided, run in command-line mode
    if args.proxy or args.target or args.ports:
        if not args.proxy or not args.target:
            print("[-] In command-line mode, both --proxy and --target are required.")
            sys.exit(1)
        config["proxy_host"], config["proxy_port"] = args.proxy.split(":")
        config["proxy_port"] = int(config["proxy_port"])
        config["target_network"] = args.target
        if args.ports:
            config["ports"] = [int(p) for p in args.ports.split(",")]
        if args.threads:
            config["threads"] = args.threads
        scan_network()
        show_summary()
    else:
        # Interactive mode
        interactive_menu()

if __name__ == "__main__":
    main()