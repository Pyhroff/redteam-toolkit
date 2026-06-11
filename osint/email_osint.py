"""
email_osint.py — Email reconnaissance (SMTP verification + breach check)

WHY this exists:
  Email addresses are gold for social engineering and spear phishing.
  Before crafting a pretext, a red teamer wants to know:
  - Does this email actually exist? (SMTP RCPT TO check)
  - What services is it registered with? (breach databases)
  - What can we infer from the domain? (MX records, SPF, DMARC)

  SPF/DMARC gaps matter: if target.com has no DMARC policy, you can spoof
  @target.com in a phishing email and it won't be rejected.

KILL CHAIN PHASE: Reconnaissance / Social Engineering prep

USAGE:
  python email_osint.py -e victim@company.com
  python email_osint.py -e victim@company.com --smtp-verify
  python email_osint.py --domain company.com

NOTE: SMTP verification may be blocked by servers that reject the RCPT TO
technique. HaveIBeenPwned API requires a free API key.

ONLY use on targets you are authorized to investigate.
REQUIRES: pip install dnspython requests
"""

import dns.resolver
import socket
import smtplib
import argparse
import re
import requests
import json
from datetime import datetime


def validate_format(email: str) -> bool:
    """Basic regex check before making network calls."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def get_mx_records(domain: str) -> list:
    """
    Query DNS MX records for a domain.
    MX records tell us which mail server accepts email for @domain.
    We need this to know which server to connect to for SMTP verification.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
    except Exception as e:
        return []


def check_spf(domain: str) -> str:
    """
    SPF = Sender Policy Framework. A DNS TXT record that lists which servers
    are allowed to send email for the domain.
    If SPF is missing → potential email spoofing vector.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return "NOT FOUND (potential spoofing vector)"


def check_dmarc(domain: str) -> str:
    """
    DMARC = Domain-based Message Authentication, Reporting and Conformance.
    Lives at _dmarc.<domain>. Policy=none means emails aren't rejected even if
    SPF/DKIM fails → a red teamer can potentially spoof @domain.
    """
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                return txt
    except Exception:
        pass
    return "NOT FOUND (no DMARC enforcement)"


def smtp_verify(email: str, mx_host: str, sender: str = "probe@probe.io") -> dict:
    """
    SMTP RCPT TO technique:
    1. Connect to the target's mail server
    2. Say EHLO, then MAIL FROM with a fake address
    3. Try RCPT TO with the target email
    4. A 250 response = the server accepted the address (user likely exists)
    5. A 550/551 = user doesn't exist

    CAVEAT: Many servers run "catch-all" policies (accept all) or block this
    technique entirely. Treat results as indicative, not definitive.
    """
    result = {"valid": None, "response": "", "error": ""}
    try:
        with smtplib.SMTP(timeout=10) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo("probe.local")
            smtp.mail(sender)
            code, msg = smtp.rcpt(email)
            result["response"] = f"{code} {msg.decode(errors='ignore')}"
            result["valid"] = (code == 250)
    except smtplib.SMTPRecipientsRefused as e:
        result["valid"] = False
        result["response"] = str(e)
    except Exception as e:
        result["error"] = str(e)
        result["valid"] = None   # inconclusive
    return result


def check_hibp(email: str, api_key: str) -> list:
    """
    HaveIBeenPwned API — checks if email appeared in known data breaches.
    Requires a free API key from https://haveibeenpwned.com/API/v3
    Returns list of breach names.
    """
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "EmailOSINT/1.0",
    }
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return [b["Name"] for b in resp.json()]
        elif resp.status_code == 404:
            return []         # no breaches found
        else:
            return [f"API error: {resp.status_code}"]
    except Exception as e:
        return [f"Request failed: {e}"]


def main():
    parser = argparse.ArgumentParser(description="Email OSINT and reconnaissance")
    parser.add_argument("-e", "--email", help="Target email address")
    parser.add_argument("--domain", help="Check a domain's email security posture")
    parser.add_argument("--smtp-verify", action="store_true",
                        help="Attempt SMTP RCPT TO email verification")
    parser.add_argument("--hibp-key", default="",
                        help="HaveIBeenPwned API key for breach lookup")
    args = parser.parse_args()

    if not args.email and not args.domain:
        parser.print_help()
        return

    print(f"\n[*] Email OSINT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if args.email:
        email = args.email
        domain = email.split("@")[1] if "@" in email else ""

        print(f"\n[*] Target email : {email}")

        if not validate_format(email):
            print("  [-] Invalid email format")
        else:
            print("  [+] Format valid")

        if domain:
            print(f"\n[*] Domain analysis: {domain}")

            mx = get_mx_records(domain)
            if mx:
                print(f"  [+] MX records:")
                for pref, host in mx:
                    print(f"      Priority {pref}: {host}")
            else:
                print("  [-] No MX records found")

            spf = check_spf(domain)
            print(f"\n  [*] SPF  : {spf}")

            dmarc = check_dmarc(domain)
            print(f"  [*] DMARC: {dmarc}")

            # Flag spoofing risk
            if "NOT FOUND" in dmarc or "none" in dmarc.lower():
                print("  [!] SPOOFING RISK: Weak or missing DMARC policy")

        if args.smtp_verify and mx:
            print(f"\n[*] SMTP verification via {mx[0][1]}...")
            result = smtp_verify(email, mx[0][1])
            if result["valid"] is True:
                print(f"  [+] LIKELY EXISTS: {result['response']}")
            elif result["valid"] is False:
                print(f"  [-] Likely doesn't exist: {result['response']}")
            else:
                print(f"  [?] Inconclusive: {result['error']}")

        if args.hibp_key:
            print(f"\n[*] Checking HaveIBeenPwned...")
            breaches = check_hibp(email, args.hibp_key)
            if breaches:
                print(f"  [!] Found in {len(breaches)} breach(es):")
                for b in breaches:
                    print(f"      - {b}")
            else:
                print("  [+] Not found in HIBP database")

    elif args.domain:
        domain = args.domain
        print(f"\n[*] Domain email posture: {domain}")

        mx = get_mx_records(domain)
        if mx:
            print(f"\n  [+] MX records:")
            for pref, host in mx:
                print(f"      Priority {pref}: {host}")
        else:
            print("\n  [-] No MX records")

        print(f"\n  [*] SPF  : {check_spf(domain)}")
        print(f"  [*] DMARC: {check_dmarc(domain)}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
