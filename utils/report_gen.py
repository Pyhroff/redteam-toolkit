"""
utils/report_gen.py — Pentest report generator from session JSON

THE PROBLEM WITH MOST REPORTS:
  After a 3-hour engagement you have findings scattered across terminal
  output, notes, screenshots. Writing a report from scratch takes longer
  than the actual test. This generates a formatted HTML report from the
  session.json you've been building automatically throughout the engagement.

GENERATES:
  - Self-contained HTML file (Bootstrap CSS, no external dependencies)
  - Cover page: target, tester, date, scope
  - Executive summary: finding counts by severity, risk rating
  - Findings table: each vulnerability with severity, location, recommendation
  - Technical appendix: open ports, credentials, tech stack, subdomains
  - CVSS-style severity color coding

USAGE:
  python utils/report_gen.py --session engagements/session_xxx.json
  python utils/report_gen.py --session engagements/session_xxx.json \
      --tester "Your Name" --org "AcmeCorp" --output report.html
  python utils/report_gen.py --session engagements/session_xxx.json --markdown
"""

import json
import argparse
import sys
from datetime import datetime
from html import escape as html_escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


SEVERITY_COLORS = {
    "CRITICAL": ("#7c0000", "#ff4d4d"),
    "HIGH":     ("#7c3a00", "#ff8c00"),
    "MEDIUM":   ("#7c6a00", "#ffd700"),
    "LOW":      ("#1a5200", "#4caf50"),
    "INFO":     ("#1a3a5c", "#5bc0de"),
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Penetration Test Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  .page {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px; }}

  /* Cover */
  .cover {{ background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border: 1px solid #30363d; border-radius: 12px; padding: 60px 50px;
            margin-bottom: 40px; text-align: center; }}
  .cover h1 {{ font-size: 2.4em; color: #58a6ff; margin-bottom: 10px; letter-spacing: 2px; }}
  .cover h2 {{ font-size: 1.3em; color: #8b949e; font-weight: 400; margin-bottom: 30px; }}
  .cover .badge {{ display: inline-block; background: #1f3a5f; color: #58a6ff;
                   border: 1px solid #58a6ff; padding: 6px 18px; border-radius: 20px;
                   font-size: 0.85em; margin: 4px; }}
  .cover .meta-table {{ margin: 30px auto; width: auto; text-align: left;
                        border-collapse: collapse; }}
  .cover .meta-table td {{ padding: 8px 20px; border-bottom: 1px solid #21262d; }}
  .cover .meta-table td:first-child {{ color: #8b949e; font-size: 0.9em; text-transform: uppercase;
                                       letter-spacing: 1px; width: 160px; }}
  .cover .meta-table td:last-child {{ color: #e6edf3; font-weight: 600; }}

  /* Section headers */
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 30px; margin-bottom: 30px; }}
  .section h3 {{ font-size: 1.2em; color: #58a6ff; text-transform: uppercase;
                 letter-spacing: 2px; margin-bottom: 20px; padding-bottom: 10px;
                 border-bottom: 1px solid #30363d; }}

  /* Risk summary cards */
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 10px; }}
  .risk-card {{ background: #0d1117; border-radius: 8px; padding: 20px; text-align: center; }}
  .risk-card .count {{ font-size: 2.5em; font-weight: 700; }}
  .risk-card .label {{ font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px;
                       color: #8b949e; margin-top: 4px; }}
  .critical {{ border: 2px solid #ff4d4d; }}  .critical .count {{ color: #ff4d4d; }}
  .high     {{ border: 2px solid #ff8c00; }}  .high .count     {{ color: #ff8c00; }}
  .medium   {{ border: 2px solid #ffd700; }}  .medium .count   {{ color: #ffd700; }}
  .low      {{ border: 2px solid #4caf50; }}  .low .count      {{ color: #4caf50; }}
  .info     {{ border: 2px solid #5bc0de; }}  .info .count     {{ color: #5bc0de; }}

  /* Overall risk rating */
  .overall-risk {{ text-align: center; padding: 20px; border-radius: 8px; margin-top: 15px;
                   background: #0d1117; border: 1px solid #30363d; }}
  .overall-risk .rating {{ font-size: 1.6em; font-weight: 700; }}

  /* Findings table */
  .findings-table {{ width: 100%; border-collapse: collapse; }}
  .findings-table th {{ background: #21262d; color: #8b949e; text-transform: uppercase;
                        font-size: 0.8em; letter-spacing: 1px; padding: 12px 15px;
                        text-align: left; }}
  .findings-table td {{ padding: 14px 15px; border-bottom: 1px solid #21262d;
                        vertical-align: top; }}
  .findings-table tr:hover td {{ background: #1c2128; }}

  .sev-badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px;
                font-size: 0.75em; font-weight: 700; letter-spacing: 1px; }}
  .sev-CRITICAL {{ background: #3d0000; color: #ff4d4d; border: 1px solid #ff4d4d; }}
  .sev-HIGH     {{ background: #3d1900; color: #ff8c00; border: 1px solid #ff8c00; }}
  .sev-MEDIUM   {{ background: #3d3200; color: #ffd700; border: 1px solid #ffd700; }}
  .sev-LOW      {{ background: #0d2900; color: #4caf50; border: 1px solid #4caf50; }}
  .sev-INFO     {{ background: #0d1e29; color: #5bc0de; border: 1px solid #5bc0de; }}

  .location {{ font-family: monospace; font-size: 0.85em; color: #79c0ff;
               word-break: break-all; }}
  .payload  {{ font-family: monospace; font-size: 0.8em; background: #0d1117;
               padding: 4px 8px; border-radius: 4px; color: #f85149;
               border: 1px solid #30363d; }}

  /* Appendix tables */
  .app-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  .app-table th {{ background: #21262d; color: #8b949e; padding: 10px 14px;
                   text-align: left; font-size: 0.8em; text-transform: uppercase; }}
  .app-table td {{ padding: 10px 14px; border-bottom: 1px solid #21262d;
                   font-family: monospace; font-size: 0.9em; }}
  .app-table tr:hover td {{ background: #1c2128; }}
  .port-open {{ color: #4caf50; font-weight: 600; }}

  /* Creds — always marked sensitive */
  .cred-row td {{ color: #ff8c00; }}
  .sensitive-banner {{ background: #3d1900; border: 1px solid #ff8c00; border-radius: 6px;
                       padding: 10px 15px; margin-bottom: 15px; color: #ff8c00;
                       font-size: 0.85em; }}

  .footer {{ text-align: center; color: #484f58; font-size: 0.8em; margin-top: 40px;
             padding-top: 20px; border-top: 1px solid #21262d; }}
  .empty {{ color: #484f58; font-style: italic; padding: 20px 0; }}
</style>
</head>
<body>
<div class="page">

<!-- COVER PAGE -->
<div class="cover">
  <h1>PENETRATION TEST REPORT</h1>
  <h2>{org}</h2>
  <div>
    <span class="badge">CONFIDENTIAL</span>
    <span class="badge">AUTHORIZED TESTING</span>
  </div>
  <table class="meta-table">
    <tr><td>Target</td><td>{target}</td></tr>
    <tr><td>Session ID</td><td>{session_id}</td></tr>
    <tr><td>Tester</td><td>{tester}</td></tr>
    <tr><td>Date</td><td>{date}</td></tr>
    <tr><td>Generated</td><td>{generated}</td></tr>
  </table>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
  <h3>Executive Summary</h3>
  <div class="summary-grid">
    <div class="risk-card critical"><div class="count">{count_critical}</div><div class="label">Critical</div></div>
    <div class="risk-card high">   <div class="count">{count_high}</div>   <div class="label">High</div></div>
    <div class="risk-card medium"> <div class="count">{count_medium}</div> <div class="label">Medium</div></div>
    <div class="risk-card low">    <div class="count">{count_low}</div>    <div class="label">Low</div></div>
    <div class="risk-card info">   <div class="count">{count_info}</div>   <div class="label">Info</div></div>
  </div>
  <div class="overall-risk">
    <div style="color:#8b949e;font-size:0.85em;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Overall Risk Rating</div>
    <div class="rating" style="color:{overall_color};">{overall_risk}</div>
  </div>
</div>

<!-- FINDINGS -->
<div class="section">
  <h3>Vulnerabilities & Findings</h3>
  {findings_html}
</div>

<!-- OPEN PORTS -->
<div class="section">
  <h3>Open Ports &amp; Services</h3>
  {ports_html}
</div>

<!-- TECH STACK -->
<div class="section">
  <h3>Technology Stack</h3>
  {tech_html}
</div>

<!-- SUBDOMAINS -->
<div class="section">
  <h3>Discovered Subdomains</h3>
  {subdomains_html}
</div>

<!-- CREDENTIALS -->
<div class="section">
  <h3>Credentials Found</h3>
  {creds_html}
</div>

<!-- WEB PATHS -->
<div class="section">
  <h3>Notable Web Paths</h3>
  {webpaths_html}
</div>

<div class="footer">
  Generated by redteam-toolkit/utils/report_gen.py &nbsp;|&nbsp;
  {generated} &nbsp;|&nbsp;
  CONFIDENTIAL — Do not distribute without authorization
</div>

</div>
</body>
</html>"""


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def esc(value) -> str:
    """Escape untrusted values before inserting them into HTML text or attributes."""
    return html_escape(str(value if value is not None else ""), quote=True)


def overall_risk(counts: dict) -> tuple:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL", "#ff4d4d"
    if counts.get("HIGH", 0) > 0:
        return "HIGH", "#ff8c00"
    if counts.get("MEDIUM", 0) > 0:
        return "MEDIUM", "#ffd700"
    if counts.get("LOW", 0) > 0:
        return "LOW", "#4caf50"
    return "INFORMATIONAL", "#5bc0de"


def build_findings_html(findings: list) -> str:
    if not findings:
        return '<p class="empty">No findings recorded.</p>'

    rows = ""
    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))
    for f in sorted_f:
        sev = str(f.get("severity", "INFO")).upper()
        if sev not in SEVERITY_ORDER:
            sev = "INFO"
        pld   = f.get("payload", "")
        rec   = f.get("recommendation", "")
        payload_html = f'<div class="payload">{esc(pld[:100])}</div>' if pld else ""
        rec_html = f'<div style="color:#8b949e;font-size:0.85em;margin-top:6px;">💡 {esc(rec)}</div>' if rec else ""
        rows += f"""
        <tr>
          <td><span class="sev-badge sev-{sev}">{sev}</span></td>
          <td>{esc(f.get('type',''))}</td>
          <td><span class="location">{esc(f.get('location',''))}</span>{payload_html}</td>
          <td>{esc(f.get('detail',''))}{rec_html}</td>
          <td style="color:#8b949e;font-size:0.8em;">{esc(str(f.get('timestamp',''))[:16])}</td>
        </tr>"""

    return f"""
    <table class="findings-table">
      <tr><th>Severity</th><th>Type</th><th>Location / Payload</th><th>Detail</th><th>Time</th></tr>
      {rows}
    </table>"""


def build_ports_html(ports: list) -> str:
    if not ports:
        return '<p class="empty">No ports recorded.</p>'
    rows = "".join(f"""
      <tr>
        <td class="port-open">{esc(p.get('port',''))}</td>
        <td>{esc(p.get('state',''))}</td>
        <td>{esc(p.get('service',''))}</td>
        <td>{esc(str(p.get('banner',''))[:80])}</td>
      </tr>""" for p in sorted(ports, key=lambda x: x["port"]))
    return f"""<table class="app-table">
      <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>{rows}</table>"""


def build_tech_html(tech: list) -> str:
    if not tech:
        return '<p class="empty">No technology data recorded.</p>'
    rows = ""
    for t in tech:
        cves = ", ".join(t.get("cve_hints", [])[:2]) or "—"
        rows += f"""
      <tr>
        <td>{esc(t.get('tech',''))}</td>
        <td>{esc(t.get('version','') or '—')}</td>
        <td style="color:#ff8c00;font-size:0.85em;">{esc(cves)}</td>
        <td style="color:#8b949e;font-size:0.8em;">{esc(str(t.get('timestamp',''))[:16])}</td>
      </tr>"""
    return f"""<table class="app-table">
      <tr><th>Technology</th><th>Version</th><th>CVE Hints</th><th>Detected</th></tr>{rows}</table>"""


def build_subdomains_html(subs: list) -> str:
    if not subs:
        return '<p class="empty">No subdomains discovered.</p>'
    rows = "".join(f"""
      <tr>
        <td>{esc(s.get('fqdn',''))}</td>
        <td>{esc(', '.join(s.get('ips',[])))}</td>
        <td style="color:#8b949e;font-size:0.8em;">{esc(str(s.get('timestamp',''))[:16])}</td>
      </tr>""" for s in subs)
    return f"""<table class="app-table">
      <tr><th>Subdomain</th><th>IP(s)</th><th>Found</th></tr>{rows}</table>"""


def build_creds_html(creds: list) -> str:
    if not creds:
        return '<p class="empty">No credentials recorded.</p>'
    banner = '<div class="sensitive-banner">⚠ SENSITIVE — Handle according to engagement rules of engagement. Do not store outside encrypted storage.</div>'
    rows = "".join(f"""
      <tr class="cred-row">
        <td>{esc(c.get('username',''))}</td>
        <td>{esc(c.get('password',''))}</td>
        <td>{esc(c.get('service',''))}</td>
        <td>{esc(c.get('host',''))}</td>
        <td style="color:#8b949e;font-size:0.8em;">{esc(str(c.get('timestamp',''))[:16])}</td>
      </tr>""" for c in creds)
    return banner + f"""<table class="app-table">
      <tr><th>Username</th><th>Password</th><th>Service</th><th>Host</th><th>Found</th></tr>{rows}</table>"""


def build_webpaths_html(paths: list) -> str:
    interesting = [p for p in paths if p.get("status") in (200, 301, 302, 403, 401)]
    if not interesting:
        return '<p class="empty">No notable web paths recorded.</p>'
    rows = ""
    for p in interesting[:50]:
        status = p.get("status", "")
        color  = "#4caf50" if status == 200 else ("#ff8c00" if status in (401, 403) else "#8b949e")
        rows += f"""
      <tr>
        <td style="color:{color};font-weight:600;">{esc(status)}</td>
        <td><span class="location">{esc(p.get('url',''))}</span></td>
        <td>{esc(p.get('size',''))} bytes</td>
        <td style="color:#8b949e;font-size:0.85em;">{esc(p.get('note',''))}</td>
      </tr>"""
    return f"""<table class="app-table">
      <tr><th>Status</th><th>URL</th><th>Size</th><th>Note</th></tr>{rows}</table>"""


def generate_markdown(session: dict, tester: str, org: str) -> str:
    """Generate a simpler Markdown report."""
    lines = [
        f"# Penetration Test Report — {session.get('target','')}",
        f"\n**Organization:** {org}",
        f"**Tester:** {tester}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        f"**Session:** {session.get('session_id','')}",
        f"\n---\n",
        "## Executive Summary\n",
    ]
    findings = session.get("findings", [])
    counts   = {s: sum(1 for f in findings if f.get("severity") == s)
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for sev, count in counts.items():
        lines.append(f"- **{sev}:** {count}")

    risk, _ = overall_risk(counts)
    lines.append(f"\n**Overall Risk: {risk}**\n")
    lines.append("## Findings\n")

    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 99))
    for i, f in enumerate(sorted_f, 1):
        lines.append(f"### {i}. [{f.get('severity','')}] {f.get('type','')}")
        lines.append(f"- **Location:** `{f.get('location','')}`")
        if f.get("detail"):
            lines.append(f"- **Detail:** {f.get('detail','')}")
        if f.get("payload"):
            lines.append(f"- **Payload:** `{f.get('payload','')}`")
        if f.get("recommendation"):
            lines.append(f"- **Recommendation:** {f.get('recommendation','')}")
        lines.append("")

    lines.append("## Open Ports\n")
    for p in sorted(session.get("ports", []), key=lambda x: x["port"]):
        lines.append(f"- `{p['port']}` {p.get('service','')} — {p.get('banner','')[:60]}")

    if session.get("credentials"):
        lines.append("\n## Credentials Found\n")
        lines.append("⚠ **SENSITIVE — Handle per Rules of Engagement**\n")
        for c in session["credentials"]:
            lines.append(f"- `{c['username']}:{c['password']}` @ {c.get('service','')}:{c.get('host','')}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Pentest report generator from session JSON")
    parser.add_argument("--session", required=True, help="Session JSON file path")
    parser.add_argument("--tester", default="Red Team Operator", help="Tester name")
    parser.add_argument("--org", default="Target Organization", help="Target organization name")
    parser.add_argument("--output", default="", help="Output file (default: report_<session_id>.html)")
    parser.add_argument("--markdown", action="store_true", help="Generate Markdown instead of HTML")
    args = parser.parse_args()

    try:
        with open(args.session) as f:
            session = json.load(f)
    except FileNotFoundError:
        print(f"[-] Session file not found: {args.session}")
        return
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON in session file: {e}")
        return

    print(f"[*] Generating report for session: {session.get('session_id','?')}")
    print(f"[*] Target: {session.get('target','?')}")

    findings = session.get("findings", [])
    counts   = {s: sum(1 for f in findings if f.get("severity") == s)
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    risk_label, risk_color = overall_risk(counts)

    # output file
    session_id = session.get("session_id", "report")
    ext = ".md" if args.markdown else ".html"
    output_path = args.output or f"report_{session_id}{ext}"

    if args.markdown:
        content = generate_markdown(session, args.tester, args.org)
    else:
        content = HTML_TEMPLATE.format(
            target=esc(session.get("target","")),
            org=esc(args.org),
            session_id=esc(session.get("session_id","")),
            tester=esc(args.tester),
            date=esc(str(session.get("created_at",""))[:10]),
            generated=esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            count_critical=counts.get("CRITICAL",0),
            count_high=counts.get("HIGH",0),
            count_medium=counts.get("MEDIUM",0),
            count_low=counts.get("LOW",0),
            count_info=counts.get("INFO",0),
            overall_risk=risk_label,
            overall_color=risk_color,
            findings_html=build_findings_html(findings),
            ports_html=build_ports_html(session.get("ports",[])),
            tech_html=build_tech_html(session.get("tech_stack",[])),
            subdomains_html=build_subdomains_html(session.get("subdomains",[])),
            creds_html=build_creds_html(session.get("credentials",[])),
            webpaths_html=build_webpaths_html(session.get("web_paths",[])),
        )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[+] Report saved: {output_path}")
    print(f"\n    Summary:")
    print(f"    Critical : {counts.get('CRITICAL',0)}")
    print(f"    High     : {counts.get('HIGH',0)}")
    print(f"    Medium   : {counts.get('MEDIUM',0)}")
    print(f"    Low      : {counts.get('LOW',0)}")
    print(f"    Ports    : {len(session.get('ports',[]))}")
    print(f"    Creds    : {len(session.get('credentials',[]))}")
    print(f"\n    Open in browser: {output_path}")


if __name__ == "__main__":
    main()
