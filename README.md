# Network Pivot Scanner

Scan internal networks through a SOCKS5 proxy. Find live hosts, open ports, and lateral movement vectors.

## Install

pip install -r requirements.txt

## Usage

1. Set up SOCKS5 proxy (e.g., ssh -D 1080 user@target)
2. Run scanner:
   python pivot_scanner.py --proxy 127.0.0.1:1080 --target 10.0.0.0/24 --ports 22,445,3389