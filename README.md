# redteam-toolkit ⚔

Advanced Python toolkit for authorized red team engagements.
Built from scratch for the BTech Cybersec → Red Team Consultant track.

> **NOT a Metasploit wrapper. Not a script-kiddie collection.**
> Every script is built with a WHY, a detection profile, and a stealthy alternative.

---

## LEGAL NOTICE

> Only use on systems you **own** or have **explicit written authorization** to test.
> Unauthorized use is illegal (IT Act 2000 / CFAA / equivalent).
> For practice: HackTheBox · TryHackMe · VulnHub · DVWA · your own VMs.

---

## What makes this different from existing frameworks

| Feature | Metasploit | Empire | reconftw | **This Toolkit** |
|---------|-----------|--------|----------|-----------------|
| OPSEC risk scoring | ❌ | ❌ | ❌ | ✅ `opsec_advisor.py` |
| Engagement session tracker | ❌ | ❌ | ❌ | ✅ `core/session.py` |
| Auto-chain orchestrator | ❌ | ❌ | Partial | ✅ `core/orchestrator.py` |
| OSINT-aware password gen | ❌ | ❌ | ❌ | ✅ `smart_passwords.py` |
| WAF detection + bypass hints | ❌ | ❌ | ❌ | ✅ `waf_detector.py` |
| SE pretext builder + Cialdini | ❌ | ❌ | ❌ | ✅ `pretext_builder.py` |
| Tech stack → CVE mapping | ❌ | ❌ | Partial | ✅ `tech_fingerprint.py` |
| Linux privesc with GTFOBins | External | External | ❌ | ✅ `privesc_linux.py` |
| LFI + wrapper + log poison | ❌ | ❌ | ❌ | ✅ `lfi_tester.py` |

---

## Windows AV — Do this first

Defender **will quarantine** these files. Add an exclusion:

```powershell
# Run PowerShell as Administrator
Add-MpPreference -ExclusionPath "C:\Users\LENOVO\OneDrive\Desktop\redteam-toolkit"
```

---

## Setup

```bash
pip install -r requirements.txt
```

---

## Full Toolkit Map

```
redteam-toolkit/
│
├── core/                          ← Session management + automation
│   ├── session.py                 ★ Engagement state tracker (all findings → JSON)
│   └── orchestrator.py            ★ Full recon pipeline, auto-chains tools
│
├── recon/                         ← Information gathering
│   ├── port_scanner.py            Multi-threaded TCP scanner + banners
│   ├── subdomain_enum.py          DNS brute-force subdomain discovery
│   ├── dir_fuzzer.py              Web directory/file fuzzer
│   ├── waf_detector.py            ★ WAF fingerprint + bypass suggestions
│   └── tech_fingerprint.py        ★ Tech stack ID → CVE mapping
│
├── exploitation/                  ← Vulnerability exploitation
│   ├── sqli_tester.py             Error/boolean/time-based SQLi detector
│   ├── ssh_brute.py               SSH credential brute-forcer
│   └── lfi_tester.py              ★ LFI + PHP wrappers + log poisoning
│
├── post_exploit/                  ← Post-compromise actions
│   ├── hash_tools.py              Hash ID + dictionary cracker
│   └── privesc_linux.py           ★ Full Linux privesc audit + GTFOBins
│
├── social_eng/                    ← Social engineering
│   └── pretext_builder.py         ★ Cialdini-based SE pretext generator
│
├── osint/                         ← Open source intelligence
│   └── email_osint.py             SMTP verify + SPF/DMARC + breach check
│
├── utils/                         ← Support tools
│   ├── payload_gen.py             Reverse shell one-liners (12 shell types)
│   ├── smart_passwords.py         ★ OSINT-aware password generator
│   └── opsec_advisor.py           ★ OPSEC risk scoring + pre-flight checklists
│
├── engagements/                   ← Auto-created session JSON files
├── wordlists/
│   └── README.md                  Where to download SecLists
└── requirements.txt
```

★ = unique to this toolkit (not in Metasploit/Empire/reconftw)

---

## Kill Chain → Script Mapping

```
RECONNAISSANCE
  └─ Port scan        → recon/port_scanner.py
  └─ Subdomain enum   → recon/subdomain_enum.py
  └─ Dir fuzzing      → recon/dir_fuzzer.py
  └─ Tech stack       → recon/tech_fingerprint.py
  └─ WAF detection    → recon/waf_detector.py
  └─ Email OSINT      → osint/email_osint.py
  └─ [ALL IN ONE]     → core/orchestrator.py  ← start here

INITIAL ACCESS
  └─ SSH brute        → exploitation/ssh_brute.py
  └─ SQLi             → exploitation/sqli_tester.py
  └─ LFI / RCE        → exploitation/lfi_tester.py
  └─ Social eng       → social_eng/pretext_builder.py

COMMAND & CONTROL
  └─ Reverse shell    → utils/payload_gen.py

CREDENTIAL ACCESS
  └─ Hash cracking    → post_exploit/hash_tools.py
  └─ Smart wordlist   → utils/smart_passwords.py

PRIVILEGE ESCALATION
  └─ Linux privesc    → post_exploit/privesc_linux.py
```

---

## Quickstart Workflows

### New engagement — start here
```bash
# Start full automated recon pipeline
python core/orchestrator.py -t 192.168.1.10 --domain target.local

# Check your OPSEC risk before doing anything noisy
python utils/opsec_advisor.py --check port_scan
python utils/opsec_advisor.py --checklist pre-engagement

# View the engagement session after scanning
python core/session.py --list
python core/session.py --load engagements/session_<id>.json --report
```

### Web app engagement
```bash
# 1. Check for WAF first
python recon/waf_detector.py -u http://target.com --active

# 2. Fingerprint tech stack
python recon/tech_fingerprint.py -u http://target.com --deep

# 3. Fuzz for hidden paths (use targeted wordlist, not 1M list)
python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt -x php,html,bak

# 4. Test for SQLi
python exploitation/sqli_tester.py -u "http://target.com/item?id=1"

# 5. Test for LFI
python exploitation/lfi_tester.py -u "http://target.com/page?file=home" --wrappers
```

### Social engineering engagement
```bash
# 1. Build email OSINT on target
python osint/email_osint.py -e cto@target.com --smtp-verify

# 2. Generate target-specific password list for later
python utils/smart_passwords.py --company "AcmeCorp" --name "John Smith" \
  --username jsmith --context "IT,security,acme" --output wordlist_acme.txt

# 3. Choose and customize a pretext
python social_eng/pretext_builder.py --list-roles
python social_eng/pretext_builder.py --role it_helpdesk --company "AcmeCorp"

# 4. Rate your pretext quality
python social_eng/pretext_builder.py --analyse
```

### Post-compromise Linux
```bash
# Transfer script to compromised host
# scp post_exploit/privesc_linux.py user@target:/tmp/

# Run the privesc audit
python3 /tmp/privesc_linux.py

# Quick mode (only highest-value checks)
python3 /tmp/privesc_linux.py --quick
```

---

## Script Reference

### `core/session.py` ★
Engagement state tracker. Every other script can log to it. Generates reports.

```bash
python core/session.py --new --target 192.168.1.10 --name "Lab Engagement"
python core/session.py --list
python core/session.py --load engagements/session_20240608_192_168_1_10_abc12345.json --report
```

**Import in your scripts:**
```python
from core.session import Session
s = Session.load_or_create(target="192.168.1.10")
s.log_port(22, "open", "SSH")
s.log_finding("SQLi", "http://target/item?id=1", severity="HIGH")
s.log_credential("admin", "password123", service="ssh")
s.save()
```

---

### `core/orchestrator.py` ★
Automated full-recon pipeline. Runs port scan → HTTP analysis → dir fuzz → subdomain enum.

```bash
python core/orchestrator.py -t 192.168.1.10
python core/orchestrator.py -t target.com --domain target.com --aggressive
python core/orchestrator.py -t 192.168.1.10 --skip-fuzz --skip-subs
```

---

### `recon/waf_detector.py` ★
WAF fingerprinting + bypass technique suggestions.

```bash
python recon/waf_detector.py -u http://target.com
python recon/waf_detector.py -u http://target.com --active       # sends attack probes
python recon/waf_detector.py -u http://target.com --active --verbose
```

---

### `recon/tech_fingerprint.py` ★
Identifies web tech stack and maps to CVEs.

```bash
python recon/tech_fingerprint.py -u http://target.com
python recon/tech_fingerprint.py -u http://target.com --deep     # checks for .env, .git, etc.
python recon/tech_fingerprint.py -u http://target.com --json     # machine-readable output
```

---

### `exploitation/lfi_tester.py` ★
LFI with traversal depths, encoding bypasses, PHP wrappers, log poisoning detection.

```bash
python exploitation/lfi_tester.py -u "http://target.com/page?file=home"
python exploitation/lfi_tester.py -u "http://target.com/page?file=home" --depth 8
python exploitation/lfi_tester.py -u "http://target.com/page?file=home" --wrappers
python exploitation/lfi_tester.py -u "http://target.com/page?file=home" --os windows
```

---

### `post_exploit/privesc_linux.py` ★
Full automated Linux privilege escalation audit. Run on compromised host.

```bash
python3 privesc_linux.py
python3 privesc_linux.py --quick        # fast: sudo/SUID/kernel only
python3 privesc_linux.py --output /tmp/report.txt
```
Checks: kernel exploits · sudo NOPASSWD · SUID + GTFOBins · cron jobs ·
writable /etc/passwd · capabilities · LD_PRELOAD · Docker escape

---

### `utils/smart_passwords.py` ★
OSINT-aware password generator. Makes target-specific wordlists.

```bash
# From company OSINT
python utils/smart_passwords.py --company "AcmeCorp" --domain acme.com \
  --output acme_wordlist.txt

# From personal OSINT (LinkedIn target)
python utils/smart_passwords.py --name "John Smith" --username jsmith \
  --birthday 1990 --context "labrador,mumbai,ACM" --output john_wordlist.txt

# Then feed to brute force
python exploitation/ssh_brute.py -t 192.168.1.10 -u jsmith -w john_wordlist.txt
```

---

### `utils/opsec_advisor.py` ★
OPSEC risk scoring. Rate any technique before running it.

```bash
# Rate a technique by name
python utils/opsec_advisor.py --check ssh_brute
python utils/opsec_advisor.py --check port_scan
python utils/opsec_advisor.py --check-all         # noise score table for all techniques

# Rate a raw command
python utils/opsec_advisor.py --rate "nmap -sV -A -p- 192.168.1.0/24"

# Pre-flight checklists
python utils/opsec_advisor.py --checklist pre-engagement
python utils/opsec_advisor.py --checklist pre-exploit
python utils/opsec_advisor.py --checklist post-compromise
```

---

### `social_eng/pretext_builder.py` ★
Generates complete SE pretexts: phone scripts, email templates, Cialdini analysis.

```bash
python social_eng/pretext_builder.py                                  # overview
python social_eng/pretext_builder.py --list-roles
python social_eng/pretext_builder.py --role it_helpdesk --company AcmeCorp
python social_eng/pretext_builder.py --role vendor --target-name "Sarah"
python social_eng/pretext_builder.py --role recruiter
python social_eng/pretext_builder.py --role it_audit
python social_eng/pretext_builder.py --analyse    # rate your own pretext
```

Available pretexts: `it_helpdesk` · `vendor` · `recruiter` · `it_audit`

---

## OPSEC Quick Reference

| Technique | Noise | Logs generated |
|-----------|-------|---------------|
| OSINT (passive) | 5/100 | None |
| Subdomain DNS brute | 30/100 | DNS server logs |
| Port scan (careful) | 55/100 | Firewall/IDS logs |
| Dir fuzzing | 60/100 | Web access.log |
| SQLi testing | 65/100 | WAF alerts, app logs |
| LFI testing | 40/100 | Web logs |
| SSH brute force | 80/100 | auth.log, fail2ban |
| Reverse shell | 85/100 | EDR, firewall, process logs |

**Rule of thumb:** always run `opsec_advisor.py --check <technique>` before anything.

---

## Practice Environments

| Platform | Best For |
|----------|----------|
| TryHackMe — Jr Pentester / Red Teaming paths | Structured learning |
| HackTheBox | Realistic machines, CVEs in the wild |
| PortSwigger Web Academy | SQLi, LFI, XSS, SSRF — free, best labs online |
| DVWA (Docker) | Local web app for all OWASP vulns |
| Metasploitable2 | Local Linux VM packed with vulns |
| VulnHub | Downloadable VMs |

```bash
# Start DVWA locally:
docker run -d -p 80:80 vulnerables/web-dvwa
```

---

## Learning Path

```
Month 1 → Recon   : orchestrator + port_scanner + dir_fuzzer + opsec_advisor
Month 2 → Web     : waf_detector + tech_fingerprint + sqli_tester + lfi_tester
Month 3 → Access  : ssh_brute + smart_passwords + payload_gen
Month 4 → Post    : hash_tools + privesc_linux
Month 5 → SE      : pretext_builder + email_osint
Month 6 → Full    : complete HTB machines, write engagement reports
```
