"""
core/orchestrator.py — Automated recon pipeline orchestrator

WHAT MAKES THIS DIFFERENT:
  Every other toolkit makes you run tools manually one by one and
  mentally keep track of what to do next. This script runs a full
  recon pipeline automatically:

  1. Port scan the target
  2. For each open port → run the appropriate tool
     - HTTP/HTTPS → tech_fingerprint + WAF detect + dir_fuzzer
     - SSH → note it for brute force
     - DNS → subdomain enum (if domain given)
     - DB ports → note for default cred checks
  3. Builds a session with everything discovered
  4. Prints a prioritized attack surface map

  Think of it as the "first 20 minutes of a pentest" automated.

KILL CHAIN PHASE: Full Reconnaissance

USAGE:
  python core/orchestrator.py -t 192.168.1.10
  python core/orchestrator.py -t target.com --domain target.com
  python core/orchestrator.py -t 192.168.1.10 --aggressive
  python core/orchestrator.py -t 192.168.1.10 --session engagements/session_xxx.json

ONLY use on systems you own or have written permission to test.
"""

import sys
import os
import socket
import threading
import argparse
import subprocess
from queue import Queue
from datetime import datetime
from pathlib import Path

# add parent dir to path so we can import our own modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.session import Session

# ─── embedded port scanner (no subprocess) ────────────────────────────────────

TOP_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
             1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,
             9090,9200,27017,11211,2181,4848,7001,9000]

SERVICE_MAP = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 1521:"Oracle", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 9200:"Elasticsearch", 27017:"MongoDB",
}

HTTP_PORTS  = {80, 443, 8080, 8443, 8888, 9090, 9000}
DB_PORTS    = {3306, 5432, 1433, 27017, 6379, 9200, 11211}
NOISY_PORTS = {445, 135, 139}   # SMB/RPC — likely to trigger IDS


def quick_scan(ip: str, ports: list, timeout: float = 1.0) -> list:
    """Fast TCP connect scan. Returns list of open port numbers."""
    open_ports = []
    lock = threading.Lock()
    q = Queue()
    for p in ports:
        q.put(p)

    def worker():
        while not q.empty():
            port = q.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
            except Exception:
                pass
            q.task_done()

    threads = [threading.Thread(target=worker) for _ in range(min(50, len(ports)))]
    for t in threads:
        t.daemon = True; t.start()
    q.join()
    return sorted(open_ports)


def grab_http_banner(ip: str, port: int) -> dict:
    """
    Send a minimal HTTP GET and parse response headers.
    Returns dict with status, server, title, powered_by etc.
    """
    import socket
    result = {"status": None, "server": "", "powered_by": "", "title": ""}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 16384:   # cap at 16KB
                    break

        text = raw.decode(errors="ignore")
        lines = text.split("\r\n")

        if lines:
            first = lines[0]
            if "HTTP/" in first:
                try:
                    result["status"] = int(first.split()[1])
                except (IndexError, ValueError):
                    pass

        for line in lines:
            ll = line.lower()
            if ll.startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif ll.startswith("x-powered-by:"):
                result["powered_by"] = line.split(":", 1)[1].strip()

        # extract <title> from body
        if "<title>" in text.lower():
            start = text.lower().find("<title>") + 7
            end   = text.lower().find("</title>")
            if end > start:
                result["title"] = text[start:end].strip()[:80]

    except Exception as e:
        result["error"] = str(e)

    return result


def run_tool(script: str, args: list, capture: bool = False):
    """
    Run a toolkit script as a subprocess.
    We use subprocess so each tool runs in its own context
    but feeds back to our shared session via the JSON file.
    """
    cmd = [sys.executable, str(Path(__file__).parent.parent / script)] + args
    print(f"\n\033[90m[EXEC] {' '.join(cmd)}\033[0m\n")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + result.stderr
    else:
        subprocess.run(cmd, timeout=300)


def print_banner(target: str, ip: str):
    print(f"""
\033[96m
  ██████╗ ██████╗  ██████╗██╗  ██╗███████╗███████╗████████╗██████╗  █████╗
 ██╔═══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
 ██║   ██║██████╔╝██║     ███████║█████╗  ███████╗   ██║   ██████╔╝███████║
 ██║   ██║██╔══██╗██║     ██╔══██║██╔══╝  ╚════██║   ██║   ██╔══██╗██╔══██║
 ╚██████╔╝██║  ██║╚██████╗██║  ██║███████╗███████║   ██║   ██║  ██║██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
\033[0m
  \033[93mTarget:\033[0m {target} ({ip})   \033[93mStarted:\033[0m {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")


def main():
    parser = argparse.ArgumentParser(description="Automated red team recon orchestrator")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("--domain", default="", help="Domain name for subdomain enum")
    parser.add_argument("--wordlist-dirs", default="wordlists/dirs.txt",
                        help="Wordlist for dir fuzzing")
    parser.add_argument("--wordlist-subs", default="wordlists/subdomains.txt",
                        help="Wordlist for subdomain enum")
    parser.add_argument("--aggressive", action="store_true",
                        help="Run more intrusive checks (louder, higher OPSEC risk)")
    parser.add_argument("--session", default="",
                        help="Load existing session JSON file")
    parser.add_argument("--skip-fuzz", action="store_true", help="Skip directory fuzzing")
    parser.add_argument("--skip-subs", action="store_true", help="Skip subdomain enum")
    args = parser.parse_args()

    # ── resolve target ──────────────────────────────────────────────────────
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Cannot resolve: {args.target}")
        return

    print_banner(args.target, ip)

    # ── session ─────────────────────────────────────────────────────────────
    if args.session:
        session = Session.load(args.session)
        print(f"[*] Loaded session: {args.session}")
    else:
        session = Session.load_or_create(
            target=args.target,
            name=f"Orchestrated engagement — {args.target}"
        )

    # ── Phase 1: Port scan ──────────────────────────────────────────────────
    print(f"\n\033[1m{'─'*55}\033[0m")
    print(f"\033[1m  PHASE 1: PORT DISCOVERY\033[0m")
    print(f"\033[1m{'─'*55}\033[0m")

    scan_ports = list(range(1, 1025)) if args.aggressive else TOP_PORTS
    print(f"[*] Scanning {len(scan_ports)} ports on {ip}...")
    session.add_opsec_noise(20 if args.aggressive else 10)

    open_ports = quick_scan(ip, scan_ports)

    if not open_ports:
        print("[-] No open ports found. Host may be firewalled or offline.")
        session.save()
        return

    print(f"\n[+] {len(open_ports)} open ports: {open_ports}")
    for port in open_ports:
        service = SERVICE_MAP.get(port, "Unknown")
        session.log_port(port, "open", service)

    session.save()

    # ── Phase 2: HTTP fingerprinting ─────────────────────────────────────────
    http_ports_found = [p for p in open_ports if p in HTTP_PORTS]
    if http_ports_found:
        print(f"\n\033[1m{'─'*55}\033[0m")
        print(f"\033[1m  PHASE 2: HTTP ANALYSIS\033[0m")
        print(f"\033[1m{'─'*55}\033[0m")

        for port in http_ports_found:
            proto = "https" if port in {443, 8443} else "http"
            url   = f"{proto}://{ip}:{port}" if port not in {80, 443} else f"{proto}://{ip}"
            print(f"\n[*] Probing {url}...")
            info = grab_http_banner(ip, port)
            print(f"  Status  : {info.get('status')}")
            print(f"  Server  : {info.get('server') or '(not disclosed)'}")
            print(f"  Powered : {info.get('powered_by') or '(not disclosed)'}")
            print(f"  Title   : {info.get('title') or '(no title)'}")

            if info.get("server"):
                session.log_tech(info["server"])
            if info.get("powered_by"):
                session.log_tech(info["powered_by"])

            # run tech fingerprinter if script exists
            tf_script = "recon/tech_fingerprint.py"
            if (Path(__file__).parent.parent / tf_script).exists():
                run_tool(tf_script, ["-u", url])
            else:
                print(f"  [!] tech_fingerprint.py not found — skipping")

        session.save()

    # ── Phase 3: Directory fuzzing ─────────────────────────────────────────
    if http_ports_found and not args.skip_fuzz:
        wl = Path(__file__).parent.parent / args.wordlist_dirs
        if wl.exists():
            print(f"\n\033[1m{'─'*55}\033[0m")
            print(f"\033[1m  PHASE 3: DIRECTORY FUZZING\033[0m")
            print(f"\033[1m{'─'*55}\033[0m")
            for port in http_ports_found[:2]:   # limit to first 2 HTTP ports
                proto = "https" if port in {443, 8443} else "http"
                url   = f"{proto}://{ip}"
                run_tool("recon/dir_fuzzer.py",
                         ["-u", url, "-w", str(wl), "--threads", "15"])
            session.save()
        else:
            print(f"\n[!] Dir wordlist not found at {wl} — skipping Phase 3")
            print(f"    Download: SecLists/Discovery/Web-Content/directory-list-2.3-small.txt")

    # ── Phase 4: Subdomain enumeration ───────────────────────────────────────
    domain = args.domain or (args.target if "." in args.target and not args.target[0].isdigit() else "")
    if domain and not args.skip_subs:
        wl = Path(__file__).parent.parent / args.wordlist_subs
        if wl.exists():
            print(f"\n\033[1m{'─'*55}\033[0m")
            print(f"\033[1m  PHASE 4: SUBDOMAIN ENUMERATION\033[0m")
            print(f"\033[1m{'─'*55}\033[0m")
            run_tool("recon/subdomain_enum.py",
                     ["-d", domain, "-w", str(wl), "--threads", "30"])
            session.save()
        else:
            print(f"\n[!] Subdomain wordlist not found — skipping Phase 4")

    # ── Phase 5: Service-specific notes ──────────────────────────────────────
    print(f"\n\033[1m{'─'*55}\033[0m")
    print(f"\033[1m  PHASE 5: ATTACK SURFACE ANALYSIS\033[0m")
    print(f"\033[1m{'─'*55}\033[0m")

    attack_surface = []

    if 22 in open_ports:
        attack_surface.append({
            "surface": "SSH (22)",
            "risk": "HIGH",
            "next": f"python exploitation/ssh_brute.py -t {args.target} -u root -w wordlists/passwords.txt",
            "noise": "Medium — generates auth.log entries"
        })
    if 445 in open_ports:
        attack_surface.append({
            "surface": "SMB (445)",
            "risk": "CRITICAL",
            "next": f"smbclient -L //{args.target}  |  enum4linux {args.target}",
            "noise": "High — SMB scans trigger IDS"
        })
        session.add_opsec_noise(15)
    if 3389 in open_ports:
        attack_surface.append({
            "surface": "RDP (3389)",
            "risk": "CRITICAL",
            "next": f"Check for BlueKeep: nmap --script rdp-vuln-ms12-020 {args.target}",
            "noise": "Medium"
        })
    for db_port in DB_PORTS.intersection(set(open_ports)):
        db_name = SERVICE_MAP.get(db_port, f"port {db_port}")
        attack_surface.append({
            "surface": f"{db_name} ({db_port})",
            "risk": "HIGH",
            "next": f"Test default credentials for {db_name}",
            "noise": "Low — single connection attempt"
        })

    if attack_surface:
        print(f"\n  {'SURFACE':<25} {'RISK':<10} NEXT STEP")
        print("  " + "-" * 70)
        for item in attack_surface:
            risk_color = "\033[91m" if item["risk"] == "CRITICAL" else "\033[93m"
            print(f"  {item['surface']:<25} {risk_color}{item['risk']:<10}\033[0m {item['next']}")
            print(f"  {'':25} {'':10} \033[90mNoise: {item['noise']}\033[0m")
    else:
        print("  No high-value attack surfaces automatically detected.")

    # ── Final report ─────────────────────────────────────────────────────────
    save_path = session.save()
    print(f"\n[*] Session saved: {save_path}")
    session.report()


if __name__ == "__main__":
    main()
