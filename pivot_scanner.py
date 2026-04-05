#!/usr/bin/env python3
"""
Network Pivot Scanner – Phoenix404
Scans internal networks via SOCKS5 proxy (SSH dynamic forwarding, Chisel, etc.)
Finds live hosts, open ports, and interesting services for lateral movement.

Usage:
    python pivot_scanner.py --proxy 127.0.0.1:1080 --target 10.0.0.0/24 --ports 22,445,3389,8080
"""

import sys
import socket
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import socks  # PySocks: pip install PySocks
import ipaddress

# Default ports to scan if not specified
DEFAULT_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443]

def setup_socks_proxy(proxy_host, proxy_port):
    """Configure global SOCKS proxy for all socket connections"""
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
    socket.socket = socks.socksocket
    print(f"[+] SOCKS5 proxy configured: {proxy_host}:{proxy_port}")

def check_host_alive(ip, timeout=2):
    """Check if host is reachable via TCP echo or ICMP-like (SYN to port 80)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 80))
        sock.close()
        return result == 0
    except:
        return False

def scan_port(ip, port, timeout=2):
    """Test if a specific TCP port is open on target"""
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
    """Attempt to grab a service banner from open port"""
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

def scan_network(target_network, ports, max_threads=50, proxy=None, proxy_port=None):
    """Main scanning function"""
    if proxy and proxy_port:
        setup_socks_proxy(proxy, proxy_port)
    
    network = ipaddress.ip_network(target_network, strict=False)
    hosts = list(network.hosts())
    print(f"[*] Scanning {len(hosts)} IPs in {target_network} for {len(ports)} ports each")
    
    alive_hosts = []
    print("[*] Checking for live hosts (TCP/80 echo)...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(check_host_alive, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                alive_hosts.append(ip)
                print(f"[+] Host alive: {ip}")
    
    if not alive_hosts:
        print("[-] No live hosts found.")
        return
    
    print(f"\n[*] Scanning {len(alive_hosts)} live hosts for open ports...")
    results = {}
    
    for ip in alive_hosts:
        print(f"\n[*] Scanning {ip}")
        open_ports = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
            for future in as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))
                    print(f"    [+] Port {port} open - {banner}")
        results[ip] = open_ports
    
    # Summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    for ip, ports in results.items():
        if ports:
            print(f"\n{ip}:")
            for port, banner in ports:
                print(f"  {port} -> {banner}")
        else:
            print(f"\n{ip}: no open ports found")
    
    # Suggest lateral movement vectors
    print("\n" + "="*60)
    print("LATERAL MOVEMENT SUGGESTIONS")
    print("="*60)
    for ip, ports in results.items():
        for port, _ in ports:
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
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Pivot Scanner via SOCKS5 proxy")
    parser.add_argument("--proxy", required=True, help="SOCKS5 proxy address:port (e.g., 127.0.0.1:1080)")
    parser.add_argument("--target", required=True, help="Target network CIDR (e.g., 10.0.0.0/24)")
    parser.add_argument("--ports", default="", help="Comma-separated ports (e.g., 22,445,3389)")
    parser.add_argument("--threads", type=int, default=50, help="Max threads (default: 50)")
    args = parser.parse_args()
    
    proxy_host, proxy_port = args.proxy.split(":")
    proxy_port = int(proxy_port)
    
    ports = DEFAULT_PORTS
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    
    scan_network(args.target, ports, max_threads=args.threads, proxy=proxy_host, proxy_port=proxy_port)