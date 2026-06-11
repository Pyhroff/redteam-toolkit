"""
utils/opsec_advisor.py — OPSEC risk scoring and pre-operation advisor

WHAT MAKES THIS UNIQUE:
  No other Python toolkit has this. Every red team action has a detection
  cost — a probability of being noticed by a defender. This tool makes
  that cost EXPLICIT before you run anything.

  Before running any technique, ask:
  • How noisy is this? (how many logs/events does it generate?)
  • What will a defender see? (exactly what log entries / alerts appear)
  • What's the MITRE ATT&CK technique number?
  • What's the stealthy alternative?

  High-performing red teamers don't just get access — they stay undetected.
  This tool makes OPSEC a first-class concern, not an afterthought.

USAGE:
  python utils/opsec_advisor.py --check port_scan
  python utils/opsec_advisor.py --check ssh_brute
  python utils/opsec_advisor.py --check-all
  python utils/opsec_advisor.py --rate "nmap -sV -A 192.168.1.0/24"
  python utils/opsec_advisor.py --checklist pre-engagement
"""

import argparse
import json
from datetime import datetime


# ─── TECHNIQUE OPSEC DATABASE ─────────────────────────────────────────────────
# Noise score: 0 (invisible) → 100 (instant IOC)
# Detection: what events a defender would see
# MITRE: ATT&CK technique ID

TECHNIQUES = {
    "port_scan": {
        "name": "TCP Port Scan",
        "noise": 55,
        "category": "Reconnaissance",
        "mitre": "T1046",
        "detection": [
            "IDS/IPS alerts: connection attempts from single source to many ports",
            "Firewall logs: sequential connection attempts",
            "syslog: multiple ICMP/TCP RST/FIN within short time window",
        ],
        "reduces_noise": [
            "Scan one port at a time with long delays (--delay in scanner)",
            "Use SYN scan only if root (half-open = less logged)",
            "Scan from a VPS/proxy close to the target subnet",
            "Scan during business hours when noise baseline is higher",
            "Use Masscan for speed but only once — or nmap for precision",
        ],
        "stealth_alt": "Single targeted port check (nc -z host port) or banner grab only",
        "timing_advice": "Use --threads 10 with 1s delay — 90% less alert density vs aggressive scan",
    },
    "ssh_brute": {
        "name": "SSH Credential Brute Force",
        "noise": 80,
        "category": "Initial Access",
        "mitre": "T1110.001",
        "detection": [
            "/var/log/auth.log: 'Failed password for' entries — 1 per attempt",
            "Fail2ban: will block your IP after 5–10 failures (default config)",
            "SIEM: multiple auth failures → authentication alert",
            "SSH honeypot: dedicated honeypot IPs may report your IP",
        ],
        "reduces_noise": [
            "Use --delay 30+ between attempts to avoid fail2ban (threshold = 5 in 10min)",
            "Try only 3-5 most likely passwords, not full wordlist",
            "Use creds obtained from OSINT/breaches first — much higher hit rate",
            "Consider password spraying (1 pass across many users) vs brute (many pass 1 user)",
            "SSH key authentication attempts don't generate 'Failed password' logs",
        ],
        "stealth_alt": "Use smart_passwords.py to generate 3-5 high-probability passwords first",
        "timing_advice": "Max 3 attempts per hour per IP to stay under most fail2ban configs",
    },
    "dir_fuzz": {
        "name": "Web Directory Fuzzing",
        "noise": 60,
        "category": "Reconnaissance",
        "mitre": "T1595.003",
        "detection": [
            "Web server access.log: hundreds of 404/403 requests from single IP",
            "WAF alerts: high request rate, attack-pattern URLs",
            "Rate limiting: 429 responses, IP blocking",
            "CloudFlare: bot detection, CAPTCHA challenges",
        ],
        "reduces_noise": [
            "Use --threads 5 with --delay to space out requests",
            "Rotate User-Agent header with each request",
            "Use a VPN/proxy to distribute source IP",
            "Prioritize small, targeted wordlists over 2M-entry lists",
            "Fuzz during traffic peaks when 404s are less anomalous",
        ],
        "stealth_alt": "Passive recon: check Wayback Machine, CommonCrawl, Google dorks first",
        "timing_advice": "10 req/sec is visible. 1 req/3sec is borderline. 1 req/30sec = basically noise",
    },
    "subdomain_enum": {
        "name": "Subdomain Enumeration (DNS Brute Force)",
        "noise": 30,
        "category": "Reconnaissance",
        "mitre": "T1596.001",
        "detection": [
            "DNS server logs: many NXDOMAIN responses from single IP (if you hit their DNS server)",
            "DNS resolver rate-limiting: Google/CF 8.8.8.8 throttles high volume",
        ],
        "reduces_noise": [
            "Use public resolvers (8.8.8.8, 1.1.1.1) — queries don't hit target's DNS",
            "Even better: use passive sources first (SecurityTrails, Shodan, crt.sh)",
            "crt.sh: curl 'https://crt.sh/?q=%.target.com&output=json' — no noise at all",
        ],
        "stealth_alt": "crt.sh + SecurityTrails API + Wayback Machine = zero noise, often better results",
        "timing_advice": "DNS brute via public resolvers is fairly safe. Direct-to-target DNS is louder.",
    },
    "sqli": {
        "name": "SQL Injection Testing",
        "noise": 65,
        "category": "Exploitation",
        "mitre": "T1190",
        "detection": [
            "WAF: SQL syntax in request body/URL → immediate block",
            "App logs: database error messages logged with the input",
            "IDS: UNION SELECT, OR 1=1, DROP TABLE patterns",
            "ModSecurity: CRS rules specifically target SQLi patterns",
        ],
        "reduces_noise": [
            "Use time-based blind SQLi — no error output, harder to detect",
            "Encode payloads to bypass signature-based detection",
            "sqlmap --level=1 --risk=1 --technique=T (time-only) for stealth",
            "Test one payload at a time manually before running automated tools",
        ],
        "stealth_alt": "Boolean-based blind SQLi generates fewer logs than error-based",
        "timing_advice": "1 probe per parameter, check response before escalating",
    },
    "lfi": {
        "name": "Local File Inclusion",
        "noise": 40,
        "category": "Exploitation",
        "mitre": "T1055",
        "detection": [
            "Web logs: ../../etc/passwd patterns in URL",
            "WAF: path traversal signatures",
            "App errors: include() failure logged in PHP error log",
        ],
        "reduces_noise": [
            "Use PHP wrapper payloads — look like normal requests to basic WAFs",
            "Encode traversal: ..%2F..%2F is less signatured than ../../",
            "Test on less-monitored endpoints (API, less-trafficked pages)",
        ],
        "stealth_alt": "php://filter/convert.base64-encode — doesn't trigger error-based LFI detections",
        "timing_advice": "One file at a time. Confirm before trying log poisoning (very noisy).",
    },
    "payload_delivery": {
        "name": "Reverse Shell / Payload Delivery",
        "noise": 85,
        "category": "Command & Control",
        "mitre": "T1059",
        "detection": [
            "EDR: process spawning /bin/sh or cmd.exe from web server process",
            "Network: outbound connection from server to unknown IP (reverse shell)",
            "SIEM: anomalous process lineage (apache → bash → nc)",
            "Firewall: outbound on unusual ports (4444, 1234 etc.)",
        ],
        "reduces_noise": [
            "Use port 443 (HTTPS) or 80 (HTTP) for reverse shell — less suspicious outbound",
            "Wrap in HTTPS traffic (socat with SSL) to avoid content inspection",
            "Prefer scheduled task / cron implants over interactive shells (less process noise)",
            "Use existing processes (python, node, php) rather than new processes",
            "Avoid netcat — it's commonly signatured. Prefer python3/socat",
        ],
        "stealth_alt": "HTTP polling C2 on port 443 with normal-looking HTTP requests",
        "timing_advice": "Interactive shell = constant traffic. Use cron-based callback instead.",
    },
    "privesc": {
        "name": "Privilege Escalation",
        "noise": 50,
        "category": "Privilege Escalation",
        "mitre": "T1068",
        "detection": [
            "/var/log/auth.log: sudo attempts",
            "Auditd: SUID binary execution, setuid syscall",
            "EDR: process with elevated privileges spawned from low-priv parent",
        ],
        "reduces_noise": [
            "SUID abuse is quiet — no logs in most default configs",
            "Avoid kernel exploits (crash risk, very loud in logs)",
            "sudo NOPASSWD abuse generates only normal sudo logs",
            "Cron-based privesc is slower but nearly invisible",
        ],
        "stealth_alt": "SUID abuse via GTFOBins — single command, single log entry at most",
        "timing_advice": "Check auditd status first: auditctl -l (rules present = monitored)",
    },
    "hash_crack": {
        "name": "Password Hash Cracking",
        "noise": 0,
        "category": "Credential Access",
        "mitre": "T1110.002",
        "detection": [
            "NONE — cracking is offline, generates zero network/system logs",
            "Only risk: where you got the hash from (see hash dump technique)",
        ],
        "reduces_noise": [
            "Nothing to reduce — offline cracking is completely silent",
        ],
        "stealth_alt": "N/A — this IS the stealthy approach",
        "timing_advice": "No time constraints. Run hashcat overnight for best results.",
    },
    "osint": {
        "name": "OSINT / Passive Reconnaissance",
        "noise": 5,
        "category": "Reconnaissance",
        "mitre": "T1593",
        "detection": [
            "Minimal — you're querying public data sources, not the target directly",
            "Target can see your IP if you visit their website directly",
            "LinkedIn/social media: profile views may be visible to target",
        ],
        "reduces_noise": [
            "Use anonymizing proxies / Tor for social media OSINT",
            "Use cached data (Google cache, Wayback) to avoid direct site visits",
            "Use API-based tools (Shodan, Hunter.io) — request goes to them, not target",
        ],
        "stealth_alt": "OSINT via third-party aggregators = zero direct target contact",
        "timing_advice": "OSINT first, always. Build full picture before any active probing.",
    },
}

# Pre-engagement checklists
CHECKLISTS = {
    "pre-engagement": [
        "Confirm written authorization (scope, Rules of Engagement signed)",
        "Document your IP addresses / test machine identifiers with the client",
        "Agree on emergency stop procedure and contact person",
        "Confirm time window for testing (business hours vs. 24/7)",
        "Check if blue team is aware (purple team) or blind (red team)",
        "Confirm out-of-scope systems (payment processors, third-party infra)",
        "Set up logging on YOUR side — full pcap or at minimum command history",
        "Agree on data handling: how are you storing captured data?",
    ],
    "pre-scan": [
        "Confirm target IP range is in scope",
        "Check if active scans are permitted (some scopes are passive-only)",
        "Note current time — scans during business hours are more common/expected",
        "Ensure scanner is pointed at the RIGHT target (double-check IP)",
        "Set conservative timing (--threads 10, delay 100ms minimum)",
        "Have emergency contact ready in case a scan causes instability",
    ],
    "pre-exploit": [
        "Document the exact vulnerability you're about to exploit",
        "Have a restore plan — know how to undo changes you make",
        "Check if the exploit could crash the target (DoS risk)",
        "Note timestamp — log your action for the report",
        "If using public exploit code, review it first (don't run blind)",
        "Test in a lab environment first if possible",
    ],
    "post-compromise": [
        "Document: time of access, method used, privilege level obtained",
        "Capture screenshots for the report",
        "List ALL changes made (files created, users added, etc.)",
        "Clean up: remove tools, reverse shell listeners, test users",
        "Do NOT access data outside of scope",
        "Do NOT use the access for anything beyond testing",
        "Note lateral movement opportunities for the report",
    ],
}


def noise_bar(score: int) -> str:
    """Visual noise level indicator."""
    filled = int(score / 10)
    color  = "\033[91m" if score > 70 else ("\033[93m" if score > 40 else "\033[92m")
    reset  = "\033[0m"
    return f"{color}{'█' * filled}{'░' * (10 - filled)}{reset} {score}/100"


def print_technique(key: str, data: dict):
    bold  = "\033[1m"
    cyan  = "\033[96m"
    yellow = "\033[93m"
    green = "\033[92m"
    reset = "\033[0m"
    dim   = "\033[90m"

    print(f"\n{cyan}{bold}{'─'*65}{reset}")
    print(f"{bold}  {data['name']} — MITRE {data['mitre']}{reset}")
    print(f"  Category: {data['category']}")
    print(f"  Noise score: {noise_bar(data['noise'])}")
    print(f"{'─'*65}")

    print(f"\n  {yellow}WHAT A DEFENDER WILL SEE:{reset}")
    for item in data["detection"]:
        print(f"    • {item}")

    print(f"\n  {green}HOW TO REDUCE NOISE:{reset}")
    for item in data["reduces_noise"]:
        print(f"    • {item}")

    print(f"\n  {green}STEALTHY ALTERNATIVE:{reset}")
    print(f"    {data['stealth_alt']}")

    print(f"\n  {dim}TIMING ADVICE:{reset}")
    print(f"    {data['timing_advice']}")

    print(f"\n  {dim}MITRE ATT&CK: https://attack.mitre.org/techniques/{data['mitre']}/{reset}")


def rate_command(cmd: str) -> int:
    """
    Heuristically rate a raw command string's OPSEC noise level.
    Returns 0-100 score.
    """
    cmd_l = cmd.lower()
    score = 10  # baseline

    noisy_patterns = {
        r"nmap\s+-[sS][aVAC]": 60,   # aggressive nmap
        r"nmap\s+-p-": 50,            # full port scan
        r"nmap\s+--script": 40,
        r"hydra|medusa|patator": 80,  # brute force tools
        r"sqlmap": 65,
        r"msfconsole|msfvenom": 75,
        r"nc\s+-e|netcat.*-e": 85,   # reverse shell via netcat
        r"bash\s+-i\s+>&": 90,
        r"chmod\s+\+s": 70,          # SUID modification
        r"wget.*http|curl.*http": 30,
        r"python.*import\s+socket": 70,
        r"sudo\s+-l": 20,
        r"find.*-perm.*4000": 25,
        r"cat\s+/etc/shadow": 30,
        r"cat\s+/etc/passwd": 15,
    }

    import re
    for pattern, noise in noisy_patterns.items():
        if re.search(pattern, cmd_l):
            score = max(score, noise)

    return min(score, 100)


def print_checklist(name: str):
    checklist = CHECKLISTS.get(name)
    if not checklist:
        print(f"[-] Unknown checklist: {name}")
        print(f"    Available: {', '.join(CHECKLISTS.keys())}")
        return
    bold  = "\033[1m"
    green = "\033[92m"
    reset = "\033[0m"

    print(f"\n{bold}  PRE-FLIGHT CHECKLIST: {name.upper()}{reset}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  " + "─" * 55)
    for i, item in enumerate(checklist, 1):
        print(f"  [{green}{'  '}{reset}] {i:2}. {item}")
    print()
    print(f"  Mark each box before proceeding. Screenshot this as part of your report.")


def main():
    parser = argparse.ArgumentParser(description="OPSEC advisor and risk scorer")
    parser.add_argument("--check", metavar="TECHNIQUE",
                        help=f"Rate a technique. Options: {', '.join(TECHNIQUES.keys())}")
    parser.add_argument("--check-all", action="store_true",
                        help="Show noise scores for all techniques")
    parser.add_argument("--rate", metavar="COMMAND",
                        help="Rate a raw command string for OPSEC noise")
    parser.add_argument("--checklist", metavar="NAME",
                        help=f"Print pre-flight checklist. Options: {', '.join(CHECKLISTS.keys())}")
    args = parser.parse_args()

    if args.check:
        key = args.check.replace("-", "_").lower()
        if key in TECHNIQUES:
            print_technique(key, TECHNIQUES[key])
        else:
            print(f"[-] Unknown technique: {key}")
            print(f"    Available: {', '.join(TECHNIQUES.keys())}")

    elif args.check_all:
        print(f"\n{'TECHNIQUE':<30} {'NOISE':<10} {'MITRE'}")
        print("─" * 55)
        for key, data in sorted(TECHNIQUES.items(), key=lambda x: -x[1]["noise"]):
            bar_text = "█" * int(data["noise"]/10) + "░" * (10 - int(data["noise"]/10))
            color = "\033[91m" if data["noise"] > 70 else ("\033[93m" if data["noise"] > 40 else "\033[92m")
            print(f"  {data['name']:<28} {color}{data['noise']:>3}/100{'\033[0m'} {data['mitre']}")

    elif args.rate:
        score = rate_command(args.rate)
        print(f"\n[*] Command: {args.rate}")
        print(f"    OPSEC noise: {noise_bar(score)}")
        if score > 70:
            print(f"    \033[91m[!] HIGH NOISE — consider a stealthy alternative\033[0m")
        elif score > 40:
            print(f"    \033[93m[~] MEDIUM NOISE — monitor for blocks/alerts\033[0m")
        else:
            print(f"    \033[92m[✓] LOW NOISE — proceed carefully\033[0m")

    elif args.checklist:
        print_checklist(args.checklist)

    else:
        parser.print_help()
        print(f"\n  Techniques available: {', '.join(TECHNIQUES.keys())}")
        print(f"  Checklists available: {', '.join(CHECKLISTS.keys())}")


if __name__ == "__main__":
    main()
