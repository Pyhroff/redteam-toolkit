"""
recon/tech_fingerprint.py — Web technology stack fingerprinter

WHY this matters for red teamers:
  Knowing the tech stack = knowing the attack surface before you even try.
  WordPress 5.6? There are 40+ CVEs for that version.
  PHP 7.2? Long out of support.
  jQuery 1.x? DOM-based XSS is likely viable.

  This script identifies:
  - Web server + version
  - CMS (WordPress, Joomla, Drupal, etc.)
  - Backend language/framework
  - JavaScript libraries + versions
  - Database hints
  - Security headers (or their absence)

  Then maps each to known CVEs and suggests exploitation paths.

KILL CHAIN PHASE: Reconnaissance

USAGE:
  python recon/tech_fingerprint.py -u http://target.com
  python recon/tech_fingerprint.py -u http://target.com --deep
  python recon/tech_fingerprint.py -u http://target.com --json

REQUIRES: pip install requests beautifulsoup4
"""

import requests
import argparse
import re
import json
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ─── TECH DETECTION DATABASE ──────────────────────────────────────────────────
# Format: tech_name → {detection_methods}
TECH_DB = {
    # CMS
    "WordPress": {
        "paths":   ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-json/"],
        "headers": [],
        "body":    ["wp-content", "wp-includes", "/wp-json/", "wordpress"],
        "meta":    ["generator"],
        "generator_pattern": r"WordPress ([\d.]+)",
        "cves": ["CVE-2023-2745 (WordPress 6.2 traversal)",
                 "CVE-2022-21663 (Object injection)",
                 "Many plugin/theme CVEs — check wpscan"],
        "tools": ["wpscan --url {url} --enumerate vp,vt,u"],
    },
    "Joomla": {
        "paths":   ["/administrator/", "/components/", "/modules/"],
        "body":    ["joomla", "mosConfig", "/components/com_"],
        "meta":    ["generator"],
        "generator_pattern": r"Joomla! ([\d.]+)",
        "cves": ["CVE-2023-23752 (Joomla 4.0-4.2 auth bypass)",
                 "CVE-2015-8562 (RCE — older versions)"],
        "tools": ["joomscan -u {url}"],
    },
    "Drupal": {
        "paths":   ["/sites/default/", "/misc/drupal.js", "/?q=node/1"],
        "body":    ["drupal", "Drupal.settings", "/misc/drupal.js"],
        "meta":    ["generator"],
        "generator_pattern": r"Drupal ([\d.]+)",
        "cves": ["CVE-2018-7600 (Drupalgeddon2 RCE)", "CVE-2019-6340 (REST RCE)"],
        "tools": ["droopescan scan drupal -u {url}"],
    },
    "Laravel": {
        "headers": ["x-powered-by"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body":    ["laravel", "Illuminate\\"],
        "cves": ["CVE-2021-3129 (Debug mode RCE — Ignition)", "CVE-2018-15133 (APP_KEY leak)"],
        "tools": ["Check /.env file, /storage/logs/laravel.log, /api/documentation"],
    },
    "Django": {
        "headers": ["x-frame-options", "x-content-type-options"],
        "cookies": ["csrftoken", "sessionid"],
        "body":    ["django", "csrfmiddlewaretoken", "CSRF"],
        "cves": ["CVE-2023-36053 (URL regex ReDos)", "Check DEBUG=True exposure"],
        "tools": ["Check /admin/, look for CSRF token bypass opportunities"],
    },
    "ASP.NET": {
        "headers": ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"],
        "cookies": ["asp.net_sessionid", "__requestverificationtoken", "viewstate"],
        "body":    ["__viewstate", "__dopostback", "asp.net"],
        "cves": ["CVE-2017-9248 (Telerik .DialogHandler)", "ViewState deserialization"],
        "tools": ["ysoserial.exe for ViewState attacks if not using MAC"],
    },
    "PHP": {
        "headers": ["x-powered-by"],
        "header_pattern": r"PHP/([\d.]+)",
        "cves": ["PHP 5.x/7.x — EOL, many unpatched CVEs", "Check php.ini exposure: /phpinfo.php"],
        "tools": ["phpinfo() page — check for disable_functions, open_basedir"],
    },
    "Ruby on Rails": {
        "cookies": ["_session_id", "_rails_session"],
        "body":    ["rails", "ruby on rails"],
        "cves": ["CVE-2019-5420 (File Content Disclosure)", "Mass assignment vulnerabilities"],
        "tools": ["Check for rails env info in error pages"],
    },
    "jQuery": {
        "body":    ["jquery"],
        "js_pattern": r"jquery[.-]([\d.]+)(\.min)?\.js",
        "cves": ["jQuery < 3.5.0: CVE-2020-11022 XSS", "jQuery < 1.6.3: CVE-2011-4969 XSS"],
        "tools": ["Check version in source, use Retire.js for full JS audit"],
    },
    "Bootstrap": {
        "body":    ["bootstrap"],
        "js_pattern": r"bootstrap[.-]([\d.]+)(\.min)?\.js",
        "cves": ["Bootstrap < 3.4.1: CVE-2019-8331 XSS"],
        "tools": [],
    },
    "Apache": {
        "server_pattern": r"Apache/([\d.]+)",
        "cves": ["CVE-2021-41773 (Path traversal + RCE)", "CVE-2021-42013 (Path traversal)"],
        "tools": ["nmap --script http-apache-negotiation {host}"],
    },
    "Nginx": {
        "server_pattern": r"nginx/([\d.]+)",
        "cves": ["CVE-2021-23017 (1-byte heap OOB)", "nginx alias misconfiguration"],
        "tools": [],
    },
    "IIS": {
        "server_pattern": r"Microsoft-IIS/([\d.]+)",
        "cves": ["CVE-2017-7269 (IIS 6.0 buffer overflow RCE)", "Check WebDAV status"],
        "tools": ["iis-shortname-scanner for 8.3 filename brute force"],
    },
    "Express.js": {
        "headers": ["x-powered-by"],
        "header_pattern": r"Express",
        "cves": ["Check for path traversal in static file serving", "SSRF via open redirect"],
        "tools": ["Check /api/ endpoints for parameter pollution"],
    },
}

# Security headers that SHOULD be present (absence = misconfiguration)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — prevents protocol downgrade attacks",
    "Content-Security-Policy": "CSP — mitigates XSS",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME-sniffing protection",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Controls browser feature access",
    "X-XSS-Protection": "Legacy XSS filter (deprecated but indicates security awareness)",
}

# Interesting paths to check for info disclosure
INFO_PATHS = [
    "/.git/HEAD",          # exposed git repo
    "/.env",               # environment variables (DB creds, API keys!)
    "/phpinfo.php",        # PHP configuration disclosure
    "/server-status",      # Apache server-status
    "/api/swagger.json",   # API schema
    "/api/openapi.json",
    "/swagger-ui.html",
    "/.htaccess",
    "/web.config",
    "/WEB-INF/web.xml",
    "/crossdomain.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
]


def detect_from_response(resp: requests.Response, verbose: bool = False) -> dict:
    """Main detection function — analyzes a single HTTP response."""
    findings = {}
    headers  = {k.lower(): v for k, v in resp.headers.items()}
    body     = resp.text
    body_low = body.lower()

    for tech, signatures in TECH_DB.items():
        matches = {"detected": False, "version": "", "evidence": []}

        # server header pattern match
        server = headers.get("server", "")
        if "server_pattern" in signatures:
            m = re.search(signatures["server_pattern"], server, re.IGNORECASE)
            if m:
                matches["detected"] = True
                matches["version"]  = m.group(1) if m.lastindex else ""
                matches["evidence"].append(f"Server header: {server}")

        # X-Powered-By header
        xpb = headers.get("x-powered-by", "")
        if "header_pattern" in signatures:
            m = re.search(signatures["header_pattern"], xpb, re.IGNORECASE)
            if m:
                matches["detected"] = True
                matches["version"]  = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                matches["evidence"].append(f"X-Powered-By: {xpb}")

        # cookie presence
        for cookie_name in signatures.get("cookies", []):
            if cookie_name.lower() in [c.lower() for c in resp.cookies.keys()]:
                matches["detected"] = True
                matches["evidence"].append(f"Cookie: {cookie_name}")

        # body keywords
        for keyword in signatures.get("body", []):
            if keyword.lower() in body_low:
                matches["detected"] = True
                matches["evidence"].append(f"Body keyword: {keyword}")
                break   # one hit is enough

        # meta generator tag
        if "generator_pattern" in signatures and BS4_AVAILABLE:
            soup = BeautifulSoup(body, "html.parser")
            gen  = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
            if gen and gen.get("content"):
                content = gen["content"]
                m = re.search(signatures["generator_pattern"], content, re.IGNORECASE)
                if m:
                    matches["detected"] = True
                    matches["version"]  = m.group(1) if m.lastindex else ""
                    matches["evidence"].append(f"<meta generator>: {content}")

        # JS file version pattern
        if "js_pattern" in signatures:
            m = re.search(signatures["js_pattern"], body, re.IGNORECASE)
            if m:
                matches["detected"] = True
                matches["version"]  = m.group(1)
                matches["evidence"].append(f"JS include: {m.group(0)}")

        if matches["detected"]:
            findings[tech] = {
                "version":  matches["version"],
                "evidence": matches["evidence"][:2],   # top 2 evidence items
                "cves":     signatures.get("cves", []),
                "tools":    signatures.get("tools", []),
            }

    return findings


def check_security_headers(resp: requests.Response) -> dict:
    """Report on which security headers are present or missing."""
    results = {}
    for header, description in SECURITY_HEADERS.items():
        present = header.lower() in {k.lower() for k in resp.headers.keys()}
        results[header] = {
            "present":     present,
            "value":       resp.headers.get(header, ""),
            "description": description,
        }
    return results


def check_info_disclosure(base_url: str, session: requests.Session) -> list:
    """Check for exposed sensitive files / information disclosure paths."""
    exposed = []
    for path in INFO_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                exposed.append({
                    "path": path, "status": 200, "size": len(resp.text),
                    "preview": resp.text[:100].replace("\n", " ")
                })
            elif resp.status_code in (401, 403):
                exposed.append({
                    "path": path, "status": resp.status_code,
                    "size": 0, "preview": "(access restricted — still notable)"
                })
        except Exception:
            pass
    return exposed


def main():
    parser = argparse.ArgumentParser(description="Web technology fingerprinter")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--deep", action="store_true",
                        help="Also check for information disclosure paths")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Output results as JSON")
    parser.add_argument("--verbose", action="store_true", help="Show evidence for each detection")
    args = parser.parse_args()

    if not BS4_AVAILABLE:
        print("[!] beautifulsoup4 not installed — meta tag detection disabled")
        print("    pip install beautifulsoup4")

    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    print(f"\n[*] Fingerprinting: {args.url}")
    print(f"[*] Deep scan: {args.deep}")
    print("-" * 65)

    try:
        resp = session.get(args.url, timeout=10, verify=False, allow_redirects=True)
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to {args.url}")
        return
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    print(f"[*] HTTP {resp.status_code} | {len(resp.text)} bytes | "
          f"Final URL: {resp.url}")

    # TECH DETECTION
    tech_findings = detect_from_response(resp, args.verbose)

    # SECURITY HEADERS
    sec_headers = check_security_headers(resp)

    # INFO DISCLOSURE
    info_exposed = []
    if args.deep:
        print(f"\n[*] Checking {len(INFO_PATHS)} info disclosure paths...")
        info_exposed = check_info_disclosure(args.url, session)

    if args.json_out:
        output = {
            "url": args.url,
            "timestamp": datetime.now().isoformat(),
            "tech_stack": tech_findings,
            "security_headers": sec_headers,
            "info_disclosure": info_exposed,
        }
        print(json.dumps(output, indent=2))
        return

    # ── PRINT RESULTS ─────────────────────────────────────────────────────────
    print(f"\n{'─'*65}")
    print(f"  TECHNOLOGY STACK")
    print(f"{'─'*65}")

    if not tech_findings:
        print("  No known technologies detected in response headers/body")
    else:
        for tech, data in tech_findings.items():
            ver_str = f" v{data['version']}" if data["version"] else ""
            print(f"\n  \033[92m[+]\033[0m \033[1m{tech}{ver_str}\033[0m")
            if args.verbose:
                for ev in data["evidence"]:
                    print(f"       Evidence: {ev}")
            if data["cves"]:
                print(f"       \033[93m⚠ CVEs:\033[0m")
                for cve in data["cves"][:2]:
                    print(f"         • {cve}")
            if data["tools"]:
                print(f"       \033[94mTools:\033[0m")
                for tool in data["tools"][:1]:
                    url_filled = tool.replace("{url}", args.url)
                    print(f"         $ {url_filled}")

    # SECURITY HEADERS
    print(f"\n{'─'*65}")
    print(f"  SECURITY HEADERS")
    print(f"{'─'*65}")
    missing = [(h, d) for h, d in sec_headers.items() if not d["present"]]
    present = [(h, d) for h, d in sec_headers.items() if d["present"]]

    for h, d in present:
        print(f"  \033[92m[✓]\033[0m {h}")
    for h, d in missing:
        print(f"  \033[91m[✗]\033[0m {h}  ← {d['description']}")

    if missing:
        print(f"\n  [!] {len(missing)} security header(s) missing "
              f"— this is a misconfiguration finding")

    # INFO DISCLOSURE
    if args.deep:
        print(f"\n{'─'*65}")
        print(f"  INFORMATION DISCLOSURE")
        print(f"{'─'*65}")
        if not info_exposed:
            print("  No sensitive paths found")
        else:
            for item in info_exposed:
                status_color = "\033[91m" if item["status"] == 200 else "\033[93m"
                print(f"  {status_color}[{item['status']}]\033[0m {item['path']}")
                if item.get("preview") and item["status"] == 200:
                    print(f"         Preview: {item['preview'][:80]}")

    print()


if __name__ == "__main__":
    main()
