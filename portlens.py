#!/usr/bin/env python3
"""
Simple multithreaded TCP connect port scanner.

Only scan hosts you own or have explicit written permission to test.

Usage examples:
    python portlens.py 127.0.0.1
    python portlens.py 192.168.1.10 -p 1-1024
    python portlens.py scanme.nmap.org -p 22,80,443 --banner
    python portlens.py 192.168.1.10 -p 1-65535 -t 200 --timeout 0.5 -o results.json
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,1000-1010' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def grab_banner(sock: socket.socket) -> str:
    """Try to read a short banner from an open connection."""
    try:
        sock.settimeout(1.0)
        return sock.recv(128).decode(errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def scan_port(ip: str, port: int, timeout: float, banner: bool):
    """Return (port, banner) if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return port, (grab_banner(sock) if banner else "")
    except OSError:
        pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("target", help="Hostname or IPv4 address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports, e.g. 80,443 or 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.target)
    except (ValueError, socket.gaierror) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Scanning {args.target} ({ip}) - {len(ports)} ports")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(scan_port, ip, p, args.timeout, args.banner)
                       for p in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, banner = result
                    service = COMMON_SERVICES.get(port, "unknown")
                    open_ports.append(
                        {"port": port, "service": service, "banner": banner})
    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    open_ports.sort(key=lambda r: r["port"])

    print(f"{'PORT':<8}{'SERVICE':<14}BANNER")
    for r in open_ports:
        print(f"{r['port']:<8}{r['service']:<14}{r['banner'][:60]}")
    print(f"\n{len(open_ports)} open port(s) found.")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"target": args.target, "ip": ip,
                       "scanned_at": datetime.now().isoformat(),
                       "open_ports": open_ports}, f, indent=2)
        print(f"Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
