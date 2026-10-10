"""
port_scanner.py — Multi-threaded TCP port scanner with banner grabbing

WHY this exists:
  Before you can attack a target, you need to know what's listening.
  Open ports = potential attack surface. Each service has known vulns.
  This mimics what nmap does at the TCP-connect level (no raw sockets needed).

USAGE:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t 192.168.1.1 -p 1-1000
  python port_scanner.py -t 192.168.1.1 -p 22,80,443,8080 --banner
  python port_scanner.py -t 192.168.1.1 --top100

ONLY use on systems you own or have written permission to test.
"""

import socket
import argparse
import threading
from queue import Empty, Queue
from datetime import datetime

# --- well-known port → service name mapping (extend as needed) ---
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

TOP_100 = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
           1723,3306,3389,5900,8080,8443,8888,9090,9200,27017,
           1080,1433,5432,6379,7001,7002,8000,8081,8888,9000,9090]

open_ports = []
lock = threading.Lock()


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to read the service banner — what the server says when you connect."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # HTTP needs a request first; everything else just sends a prompt
            if port in (80, 8080, 8000, 8081):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:100]          # cap at 100 chars
    except Exception:
        return ""


def scan_port(ip: str, port: int, grab: bool, timeout: float):
    """Attempt a TCP connect to ip:port. If it succeeds, port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))   # returns 0 on success
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(ip, port) if grab else ""
                with lock:
                    open_ports.append((port, service, banner))
    except Exception:
        pass


def worker(queue: Queue, ip: str, grab: bool, timeout: float):
    """Thread worker — pulls ports off the queue until empty."""
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            return
        try:
            scan_port(ip, port, grab, timeout)
        except Exception as exc:
            print(f"[-] Port {port} scan failed: {exc}")
        finally:
            queue.task_done()


def parse_ports(port_arg: str) -> list:
    """Parse '22,80,100-200' style input into a flat list of ints."""
    ports = []
    for part in port_arg.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP port scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range or list (e.g. 22,80 or 1-1000)")
    parser.add_argument("--top100", action="store_true", help="Scan common top-100 ports")
    parser.add_argument("--banner", action="store_true", help="Attempt to grab service banners")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Cannot resolve host: {args.target}")
        return

    ports = TOP_100 if args.top100 else parse_ports(args.ports)

    print(f"\n[*] Scanning {args.target} ({ip})")
    print(f"[*] Ports: {len(ports)} | Threads: {args.threads} | Banner: {args.banner}")
    print(f"[*] Started: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 55)

    q = Queue()
    for p in ports:
        q.put(p)

    threads = []
    for _ in range(min(args.threads, len(ports))):
        t = threading.Thread(target=worker, args=(q, ip, args.banner, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    open_ports.sort(key=lambda x: x[0])
    print(f"\n{'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'BANNER'}")
    print("-" * 55)
    for port, service, banner in open_ports:
        print(f"{port:<8} {'OPEN':<8} {service:<12} {banner}")

    print(f"\n[+] {len(open_ports)} open port(s) found")
    print(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
