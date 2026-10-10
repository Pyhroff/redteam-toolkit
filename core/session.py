"""
core/session.py — Engagement session tracker

THE PROBLEM WITH MOST TOOLKITS:
  You run 10 different tools across a 3-hour engagement and by the end
  you can't remember which ports were open, what creds you found, or
  what you've already tried. Most frameworks don't solve this.

THIS SOLVES IT:
  Every script in this toolkit can import Session and call session.log().
  Everything flows into one timestamped JSON file — open ports, found paths,
  credentials, vulnerabilities, notes. At any point, call session.report()
  for a clean summary of everything discovered so far.

USAGE (standalone):
  python core/session.py --new --target 192.168.1.10 --name "Lab Engagement"
  python core/session.py --load engagements/session_20240608_lab.json --report
  python core/session.py --list

USAGE (from other scripts):
  from core.session import Session
  s = Session.load_or_create(target="192.168.1.10")
  s.log_port(22, "open", "SSH", "OpenSSH 8.2")
  s.log_finding("SQLi", "http://target/item?id=1", severity="HIGH")
  s.log_credential("admin", "password123", service="ssh")
  s.save()
"""

import json
import os
import uuid
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional

SESSIONS_DIR = Path(__file__).parent.parent / "engagements"


class Session:
    """
    Central engagement state object. One session per target engagement.
    Serializes to/from JSON so state persists between script invocations.
    """

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",   # red
        "HIGH":     "\033[93m",   # yellow
        "MEDIUM":   "\033[94m",   # blue
        "LOW":      "\033[92m",   # green
        "INFO":     "\033[0m",    # reset
        "RESET":    "\033[0m",
    }

    def __init__(self, target: str, name: str = "", session_id: str = None):
        self.session_id   = session_id or str(uuid.uuid4())[:8]
        self.target       = target
        self.name         = name or f"Engagement on {target}"
        self.created_at   = datetime.now().isoformat()
        self.updated_at   = datetime.now().isoformat()
        self.opsec_score  = 0   # cumulative noise score (higher = noisier)

        # structured finding buckets
        self.ports        : list[dict] = []
        self.subdomains   : list[dict] = []
        self.web_paths    : list[dict] = []
        self.findings     : list[dict] = []   # vulns, misconfigs
        self.credentials  : list[dict] = []
        self.notes        : list[dict] = []
        self.tech_stack   : list[dict] = []
        self.waf_info     : dict       = {}
        self.target_profile: dict      = {}

    # ─── LOGGING METHODS ──────────────────────────────────────────────────────

    def log_port(self, port: int, state: str, service: str = "",
                 banner: str = "", source: str = ""):
        """Record an open port finding."""
        entry = {
            "port": port, "state": state, "service": service,
            "banner": banner, "source": source,
            "timestamp": _ts()
        }
        # avoid duplicates
        if not any(p["port"] == port for p in self.ports):
            self.ports.append(entry)
            self._print_log("PORT", f"{port}/tcp {state} — {service} {banner[:40]}")
        self._touch()

    def log_subdomain(self, fqdn: str, ips: list):
        entry = {"fqdn": fqdn, "ips": ips, "timestamp": _ts()}
        if not any(s["fqdn"] == fqdn for s in self.subdomains):
            self.subdomains.append(entry)
            self._print_log("SUBDOMAIN", f"{fqdn} → {', '.join(ips)}")
        self._touch()

    def log_web_path(self, url: str, status: int, size: int = 0, note: str = ""):
        entry = {"url": url, "status": status, "size": size,
                 "note": note, "timestamp": _ts()}
        self.web_paths.append(entry)
        self._touch()

    def log_finding(self, vuln_type: str, location: str,
                    detail: str = "", severity: str = "MEDIUM",
                    payload: str = "", recommendation: str = ""):
        """
        Record a vulnerability or misconfiguration.
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
        """
        severity = severity.upper()
        entry = {
            "type": vuln_type, "location": location, "detail": detail,
            "severity": severity, "payload": payload,
            "recommendation": recommendation, "timestamp": _ts()
        }
        self.findings.append(entry)
        color = self.SEVERITY_COLORS.get(severity, "")
        reset = self.SEVERITY_COLORS["RESET"]
        self._print_log("FINDING", f"{color}[{severity}]{reset} {vuln_type} @ {location}")
        self._touch()

    def log_credential(self, username: str, password: str,
                       service: str = "", host: str = "", note: str = ""):
        """Record a discovered credential pair."""
        entry = {
            "username": username, "password": password,
            "service": service, "host": host or self.target,
            "note": note, "timestamp": _ts()
        }
        self.credentials.append(entry)
        self._print_log("CRED", f"\033[91m{username}:{password}\033[0m @ {service}:{host}")
        self._touch()

    def log_tech(self, tech: str, version: str = "", cve_hints: list = None):
        """Record identified technology."""
        entry = {"tech": tech, "version": version,
                 "cve_hints": cve_hints or [], "timestamp": _ts()}
        if not any(t["tech"] == tech for t in self.tech_stack):
            self.tech_stack.append(entry)
            hint = f" (CVEs: {', '.join(cve_hints[:2])})" if cve_hints else ""
            self._print_log("TECH", f"{tech} {version}{hint}")
        self._touch()

    def log_note(self, text: str, category: str = "general"):
        entry = {"text": text, "category": category, "timestamp": _ts()}
        self.notes.append(entry)
        self._touch()

    def add_opsec_noise(self, score: int):
        """Add to cumulative OPSEC noise score. 100+ = very loud."""
        self.opsec_score += score
        self._touch()

    # ─── PERSISTENCE ──────────────────────────────────────────────────────────

    def save(self, path: str = None) -> str:
        """Serialize session to JSON file. Returns the path."""
        SESSIONS_DIR.mkdir(exist_ok=True)
        if path is None:
            date_str = datetime.now().strftime("%Y%m%d")
            slug = self.target.replace(".", "_").replace(":", "_")
            path = SESSIONS_DIR / f"session_{date_str}_{slug}_{self.session_id}.json"
        self._touch()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._to_dict(), f, indent=2)
        return str(path)

    @classmethod
    def load(cls, path: str) -> "Session":
        """Load a session from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        s = cls(target=data["target"], name=data.get("name", ""),
                session_id=data.get("session_id"))
        s.created_at    = data.get("created_at", _ts())
        s.updated_at    = data.get("updated_at", s.created_at)
        s.opsec_score   = data.get("opsec_score", 0)
        s.ports         = data.get("ports", [])
        s.subdomains    = data.get("subdomains", [])
        s.web_paths     = data.get("web_paths", [])
        s.findings      = data.get("findings", [])
        s.credentials   = data.get("credentials", [])
        s.notes         = data.get("notes", [])
        s.tech_stack    = data.get("tech_stack", [])
        s.waf_info      = data.get("waf_info", {})
        s.target_profile = data.get("target_profile", {})
        return s

    @classmethod
    def load_or_create(cls, target: str, name: str = "") -> "Session":
        """
        Look for an existing today's session for this target.
        If found, load and continue it. Otherwise create fresh.
        Enables seamless multi-tool chaining without manual session management.
        """
        SESSIONS_DIR.mkdir(exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        slug = target.replace(".", "_").replace(":", "_")
        # find any session matching today + target
        for f in SESSIONS_DIR.glob(f"session_{date_str}_{slug}_*.json"):
            print(f"\033[94m[SESSION] Continuing session: {f.name}\033[0m")
            return cls.load(str(f))
        # nothing found — start fresh
        s = cls(target=target, name=name)
        print(f"\033[92m[SESSION] New session started: {s.session_id} → {target}\033[0m")
        return s

    # ─── REPORTING ────────────────────────────────────────────────────────────

    def report(self, verbose: bool = False):
        """Print a structured engagement summary to stdout."""
        reset = "\033[0m"
        bold  = "\033[1m"
        cyan  = "\033[96m"
        yellow = "\033[93m"
        red   = "\033[91m"
        green = "\033[92m"

        print(f"\n{bold}{'='*65}{reset}")
        print(f"{bold}  ENGAGEMENT REPORT — {self.name}{reset}")
        print(f"  Target   : {self.target}")
        print(f"  Session  : {self.session_id}")
        print(f"  Created  : {self.created_at[:19]}")
        opsec_color = red if self.opsec_score > 60 else (yellow if self.opsec_score > 30 else green)
        print(f"  OPSEC noise score: {opsec_color}{self.opsec_score}/100{reset}")
        print(f"{'='*65}")

        # PORTS
        print(f"\n{cyan}{bold}[OPEN PORTS] ({len(self.ports)} found){reset}")
        for p in sorted(self.ports, key=lambda x: x["port"]):
            print(f"  {p['port']:<6} {p['service']:<14} {p.get('banner', '')[:50]}")

        # SUBDOMAINS
        if self.subdomains:
            print(f"\n{cyan}{bold}[SUBDOMAINS] ({len(self.subdomains)} found){reset}")
            for s in self.subdomains:
                print(f"  {s['fqdn']:<45} {', '.join(s['ips'])}")

        # WEB PATHS
        if self.web_paths:
            print(f"\n{cyan}{bold}[WEB PATHS] ({len(self.web_paths)} found){reset}")
            for w in self.web_paths[:20]:
                print(f"  [{w['status']}] {w['url']}")

        # TECH STACK
        if self.tech_stack:
            print(f"\n{cyan}{bold}[TECH STACK]{reset}")
            for t in self.tech_stack:
                cves = f" ⚠ CVEs: {', '.join(t['cve_hints'][:2])}" if t.get("cve_hints") else ""
                print(f"  {t['tech']} {t.get('version','')}{cves}")

        # FINDINGS — sorted by severity
        if self.findings:
            print(f"\n{cyan}{bold}[VULNERABILITIES/FINDINGS]{reset}")
            sorted_findings = sorted(self.findings,
                                     key=lambda x: self.SEVERITY_ORDER.get(x["severity"], 99))
            for f in sorted_findings:
                sev_color = self.SEVERITY_COLORS.get(f["severity"], "")
                print(f"  {sev_color}[{f['severity']:<8}]{reset} {f['type']}")
                print(f"           @ {f['location']}")
                if f.get("detail") and verbose:
                    print(f"           {f['detail']}")

        # CREDENTIALS
        if self.credentials:
            print(f"\n{red}{bold}[CREDENTIALS FOUND — HANDLE WITH CARE]{reset}")
            for c in self.credentials:
                print(f"  {c['service']:<8} {c['username']}:{c['password']}  @ {c['host']}")

        # WAF
        if self.waf_info:
            print(f"\n{cyan}{bold}[WAF DETECTED]{reset}")
            print(f"  {self.waf_info}")

        # NOTES
        if self.notes and verbose:
            print(f"\n{cyan}{bold}[NOTES]{reset}")
            for n in self.notes:
                print(f"  [{n['category']}] {n['text']}")

        # ATTACK SUGGESTIONS
        self._print_attack_suggestions()
        print(f"\n{'='*65}\n")

    def _print_attack_suggestions(self):
        """Based on what was found, suggest logical next steps."""
        bold  = "\033[1m"
        yellow = "\033[93m"
        reset = "\033[0m"

        suggestions = []
        open_ports = {p["port"] for p in self.ports if p["state"] == "open"}

        if 22 in open_ports and not any(c["service"] == "ssh" for c in self.credentials):
            suggestions.append("SSH on 22 found — try ssh_brute.py with common credentials")
        if any(p in open_ports for p in [80, 443, 8080, 8443]):
            suggestions.append("HTTP service found — run dir_fuzzer.py + tech_fingerprint.py")
        if 3306 in open_ports:
            suggestions.append("MySQL on 3306 — test for remote login, check for default creds")
        if 5432 in open_ports:
            suggestions.append("PostgreSQL on 5432 — check for remote login")
        if 445 in open_ports:
            suggestions.append("SMB on 445 — run enum4linux / check for EternalBlue")
        if 3389 in open_ports:
            suggestions.append("RDP on 3389 — check for BlueKeep (CVE-2019-0708)")
        if any(f["type"] == "SQLi" for f in self.findings):
            suggestions.append("SQLi detected — run sqlmap for full database extraction")
        if any(f["type"] == "LFI" for f in self.findings):
            suggestions.append("LFI detected — test for log poisoning → RCE")
        if self.credentials:
            suggestions.append("Credentials found — test reuse with cred_sprayer.py")

        if suggestions:
            print(f"\n{yellow}{bold}[SUGGESTED NEXT STEPS]{reset}")
            for i, s in enumerate(suggestions, 1):
                print(f"  {i}. {s}")

    # ─── HELPERS ──────────────────────────────────────────────────────────────

    def _to_dict(self) -> dict:
        return {
            "session_id": self.session_id, "target": self.target,
            "name": self.name, "created_at": self.created_at,
            "updated_at": self.updated_at, "opsec_score": self.opsec_score,
            "ports": self.ports, "subdomains": self.subdomains,
            "web_paths": self.web_paths, "findings": self.findings,
            "credentials": self.credentials, "notes": self.notes,
            "tech_stack": self.tech_stack, "waf_info": self.waf_info,
            "target_profile": self.target_profile,
        }

    def _touch(self):
        self.updated_at = datetime.now().isoformat()

    def _print_log(self, category: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\033[90m[{ts}]\033[0m \033[96m[{category}]\033[0m {message}")


def _ts() -> str:
    return datetime.now().isoformat()


def list_sessions():
    SESSIONS_DIR.mkdir(exist_ok=True)
    files = sorted(SESSIONS_DIR.glob("session_*.json"))
    if not files:
        print("No sessions found.")
        return
    print(f"\n{'FILE':<50} {'TARGET':<20} {'FINDINGS'}")
    print("-" * 80)
    for f in files:
        try:
            with open(f) as fh:
                d = json.load(fh)
            print(f"  {f.name:<48} {d.get('target','?'):<20} "
                  f"ports:{len(d.get('ports',[]))} "
                  f"vulns:{len(d.get('findings',[]))} "
                  f"creds:{len(d.get('credentials',[]))}")
        except Exception:
            print(f"  {f.name} (could not read)")


def main():
    parser = argparse.ArgumentParser(description="Engagement session manager")
    parser.add_argument("--new", action="store_true", help="Start new session")
    parser.add_argument("--target", help="Target IP/domain")
    parser.add_argument("--name", default="", help="Engagement name")
    parser.add_argument("--load", metavar="FILE", help="Load existing session")
    parser.add_argument("--report", action="store_true", help="Print session report")
    parser.add_argument("--list", action="store_true", help="List all sessions")
    parser.add_argument("--verbose", action="store_true", help="Verbose report")
    args = parser.parse_args()

    if args.list:
        list_sessions()
        return

    if args.new and args.target:
        s = Session(target=args.target, name=args.name)
        path = s.save()
        print(f"[+] Session created: {path}")
        return

    if args.load:
        s = Session.load(args.load)
        if args.report:
            s.report(verbose=args.verbose)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
