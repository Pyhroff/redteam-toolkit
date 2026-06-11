"""
recon/network_mapper.py — Subnet sweeper + ASCII network topology mapper

WHY THIS MATTERS:
  After initial access, you need to understand the NETWORK you're inside.
  - What other hosts exist on this subnet?
  - What services are they running?
  - Which ones are servers vs workstations?
  - What's the pivot path to the next target?

  This script sweeps a CIDR range, identifies live hosts, does a quick
  service fingerprint on each, and draws an ASCII network map.

DISCOVERY METHODS:
  1. ICMP ping (fastest — may be blocked by host firewalls)
  2. TCP connect to common ports (slower, works through firewalls)
  3. Combined (ICMP first, TCP fallback for non-responding hosts)

KILL CHAIN PHASE: Discovery / Lateral Movement prep

USAGE:
  python recon/network_mapper.py --range 192.168.1.0/24
  python recon/network_mapper.py --range 10.0.0.0/24 --method tcp
  python recon/network_mapper.py --range 192.168.1.0/24 --ports 22,80,443,3389
  python recon/network_mapper.py --range 192.168.1.0/24 --deep
  python recon/network_mapper.py --range 192.168.1.1-192.168.1.50

NOTE: ICMP ping requires admin/root on Windows. TCP method works without.
ONLY use on networks you own or have written permission to test.
"""

import socket
import struct
import argparse
import threading
import ipaddress
import subprocess
import platform
import sys
import re
from queue import Queue
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Service classification — what kind of machine is it?
SERVICE_ROLES = {
    frozenset([22]):                "Linux server (SSH)",
    frozenset([22, 80]):            "Linux web server",
    frozenset([22, 80, 443]):       "Linux web server (HTTPS)",
    frozenset([22, 3306]):          "Linux DB server",
    frozenset([80, 443]):           "Web server",
    frozenset([3389]):              "Windows workstation/server (RDP)",
    frozenset([3389, 445]):         "Windows server (RDP+SMB)",
    frozenset([445]):               "Windows file server (SMB)",
    frozenset([445, 135]):          "Windows domain machine",
    frozenset([1433]):              "MSSQL server",
    frozenset([3306]):              "MySQL server",
    frozenset([5432]):              "PostgreSQL server",
    frozenset([27017]):             "MongoDB server",
    frozenset([6379]):              "Redis server",
    frozenset([9200]):              "Elasticsearch node",
    frozenset([21]):                "FTP server",
    frozenset([25]):                "Mail server (SMTP)",
}

QUICK_SCAN_PORTS = [22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]

PORT_SERVICES = {
    21: "FTP",    22: "SSH",   23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",  135: "RPC",    139: "NetBIOS",
    443: "HTTPS", 445: "SMB",  1433: "MSSQL", 3306: "MySQL",
    3389: "RDP",  5432: "PG",  6379: "Redis", 8080: "HTTP-alt",
    9200: "ES",   27017: "Mongo",
}

results = {}
results_lock = threading.Lock()


def tcp_ping(ip: str, ports: list, timeout: float = 0.8) -> bool:
    """Check if host is alive by attempting TCP connect to any of the given ports."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def icmp_ping(ip: str, timeout: int = 1) -> bool:
    """OS-level ping command (works on Windows and Linux)."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
        return False


def quick_port_scan(ip: str, ports: list, timeout: float = 0.8) -> list:
    """Return list of open ports from the provided list."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def classify_host(open_ports: list) -> str:
    """Guess host role based on open ports."""
    port_set = frozenset(open_ports)
    # exact match first
    if port_set in SERVICE_ROLES:
        return SERVICE_ROLES[port_set]
    # partial match (subset of known role)
    best_match = "Unknown device"
    best_score = 0
    for role_ports, role_name in SERVICE_ROLES.items():
        match = len(port_set & role_ports)
        if match > best_score:
            best_score = match
            best_match = role_name
    return best_match if best_score > 0 else "Unknown device"


def get_hostname(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_host(ip: str, method: str, scan_ports: list, deep: bool):
    """Discover and fingerprint a single host."""
    alive = False

    if method in ("icmp", "combined"):
        alive = icmp_ping(ip)

    if not alive and method in ("tcp", "combined"):
        alive = tcp_ping(ip, [22, 80, 443, 445, 3389], timeout=1.0)

    if not alive:
        return

    # host is live — enumerate it
    open_ports = quick_port_scan(ip, scan_ports) if not deep else quick_port_scan(ip, list(range(1, 1025)))
    hostname   = get_hostname(ip)
    role       = classify_host(open_ports)

    with results_lock:
        results[ip] = {
            "ip":        ip,
            "hostname":  hostname,
            "open_ports": open_ports,
            "role":       role,
        }
    ports_str = ",".join(str(p) for p in open_ports[:8])
    print(f"  \033[92m[+]\033[0m {ip:<18} {hostname[:25]:<26} [{ports_str}]  {role}")


def worker(queue: Queue, method: str, scan_ports: list, deep: bool):
    while not queue.empty():
        ip = queue.get()
        scan_host(ip, method, scan_ports, deep)
        queue.task_done()


def parse_range(range_str: str) -> list:
    """Parse CIDR, range (1.1.1.1-1.1.1.50), or single IP."""
    if "/" in range_str:
        return [str(ip) for ip in ipaddress.ip_network(range_str, strict=False).hosts()]
    elif "-" in range_str:
        parts = range_str.split("-")
        if len(parts) == 2:
            start = ipaddress.ip_address(parts[0].strip())
            end_parts = parts[0].strip().rsplit(".", 1)
            end_octet = int(parts[1].strip())
            end = ipaddress.ip_address(f"{end_parts[0]}.{end_octet}")
            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current += 1
            return ips
    return [range_str]


def draw_network_map(host_results: dict, gateway: str = ""):
    """Draw ASCII network topology."""
    cyan  = "\033[96m"
    green = "\033[92m"
    yellow = "\033[93m"
    red   = "\033[91m"
    bold  = "\033[1m"
    reset = "\033[0m"
    dim   = "\033[90m"

    print(f"\n{bold}{'─'*70}{reset}")
    print(f"{bold}  NETWORK MAP{reset}")
    print(f"{'─'*70}")

    if not host_results:
        print("  No live hosts found.")
        return

    # Group by subnet
    print(f"""
{dim}        [Internet]{reset}
            │
        {yellow}[Gateway]{reset}{f' {gateway}' if gateway else ''}
            │
    ┌───────┴────────────┐
    │     Local Subnet    │
    └───────┬────────────┘
""")

    # Sort by IP
    sorted_hosts = sorted(host_results.items(),
                          key=lambda x: [int(o) for o in x[0].split(".")])

    for ip, info in sorted_hosts:
        ports    = info["open_ports"]
        role     = info["role"]
        hostname = info["hostname"]

        # pick color by role
        if any(p in ports for p in [3389, 445]):
            role_color = yellow   # Windows
        elif any(p in ports for p in [22]):
            role_color = green    # Linux
        elif any(p in ports for p in [80, 443, 8080]):
            role_color = cyan     # Web server
        else:
            role_color = reset

        port_tags = " ".join(
            f"[{PORT_SERVICES.get(p, str(p))}]" for p in ports[:6]
        )

        hostname_str = f" ({hostname})" if hostname else ""
        print(f"    ├── {role_color}{bold}{ip}{reset}{hostname_str}")
        print(f"    │   ├── Role  : {role}")
        print(f"    │   └── Ports : {port_tags or '(none detected)'}")
        print(f"    │")

    print(f"    └── (end of discovered hosts)")

    # ATTACK SURFACE SUMMARY
    print(f"\n{bold}{'─'*70}{reset}")
    print(f"{bold}  ATTACK SURFACE{reset}")
    print(f"{'─'*70}")

    for ip, info in sorted_hosts:
        ports = set(info["open_ports"])
        attacks = []

        if 22 in ports:
            attacks.append(f"  ssh {ip}  →  try ssh_brute.py or key auth")
        if 445 in ports:
            attacks.append(f"  smbclient -L //{ip}  →  enum4linux {ip}")
        if 3389 in ports:
            attacks.append(f"  RDP: xfreerdp /u:admin /v:{ip}  →  check BlueKeep")
        if 80 in ports or 443 in ports:
            attacks.append(f"  http://{ip}  →  run waf_detector + dir_fuzzer + tech_fingerprint")
        if 3306 in ports:
            attacks.append(f"  mysql -h {ip} -u root  →  test default creds")
        if 6379 in ports:
            attacks.append(f"  redis-cli -h {ip}  →  check for unauthenticated access")
        if 27017 in ports:
            attacks.append(f"  mongo {ip}  →  check for unauthenticated access")

        if attacks:
            print(f"\n  {bold}{ip}{reset} ({info['role']})")
            for a in attacks:
                print(f"    • {a}")


def main():
    parser = argparse.ArgumentParser(description="Subnet sweeper + network mapper")
    parser.add_argument("--range", required=True,
                        help="Target range: CIDR (192.168.1.0/24), range (192.168.1.1-50), or single IP")
    parser.add_argument("--method", choices=["icmp", "tcp", "combined"], default="combined",
                        help="Discovery method (default: combined)")
    parser.add_argument("--ports", default="",
                        help="Custom ports to scan (comma-separated). Default: top 15")
    parser.add_argument("--threads", type=int, default=50,
                        help="Thread count (default: 50)")
    parser.add_argument("--deep", action="store_true",
                        help="Full 1-1024 port scan per host (slower)")
    parser.add_argument("--gateway", default="",
                        help="Gateway IP to label on the map")
    args = parser.parse_args()

    # ports to scan
    if args.ports:
        scan_ports = [int(p.strip()) for p in args.ports.split(",")]
    else:
        scan_ports = QUICK_SCAN_PORTS

    # expand IP range
    try:
        ip_list = parse_range(args.range)
    except Exception as e:
        print(f"[-] Invalid range: {e}")
        return

    print(f"\n\033[1m{'─'*70}\033[0m")
    print(f"\033[1m  NETWORK MAPPER\033[0m")
    print(f"{'─'*70}")
    print(f"  Range    : {args.range} ({len(ip_list)} addresses)")
    print(f"  Method   : {args.method}")
    print(f"  Ports    : {scan_ports}")
    print(f"  Threads  : {args.threads}")
    print(f"  Started  : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'─'*70}\n")
    print(f"  {'IP':<20} {'HOSTNAME':<28} PORTS  ROLE")
    print(f"  {'─'*68}")

    q = Queue()
    for ip in ip_list:
        q.put(ip)

    threads = []
    for _ in range(min(args.threads, len(ip_list))):
        t = threading.Thread(target=worker, args=(q, args.method, scan_ports, args.deep))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    print(f"\n  Found: {len(results)} live host(s) out of {len(ip_list)} addresses scanned")
    print(f"  Finished: {datetime.now().strftime('%H:%M:%S')}")

    if results:
        draw_network_map(results, gateway=args.gateway)

    print()


if __name__ == "__main__":
    main()
