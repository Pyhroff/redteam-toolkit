"""
social_eng/pretext_builder.py — Social engineering pretext generator

WHY THIS EXISTS:
  Praising — your SE psychology focus means you need more than just "lie to people."
  A good pretext has:
    • A believable identity (who are you?)
    • An authority hook (why should they listen?)
    • An emotional lever (why should they act NOW?)
    • An exit strategy (how do you end cleanly?)

  This script generates complete pretexts based on target role/department,
  maps the psychological triggers being used, and rates pretext quality.

  THIS IS THE CIALDINI FRAMEWORK AUTOMATED.

PSYCHOLOGICAL TRIGGERS IMPLEMENTED:
  1. Authority     — impersonating IT, management, vendors, auditors
  2. Urgency/Fear  — "account will be suspended", "security breach"
  3. Reciprocity   — offer something first, then ask
  4. Social proof  — "your colleague John already verified"
  5. Scarcity      — "only you can approve this in time"
  6. Liking        — match their tone, common ground, compliments

USAGE:
  python social_eng/pretext_builder.py --role helpdesk --target-role employee
  python social_eng/pretext_builder.py --role vendor --target-role finance
  python social_eng/pretext_builder.py --role it_audit --company "AcmeCorp"
  python social_eng/pretext_builder.py --list-roles
  python social_eng/pretext_builder.py --analyse (rate your own pretext)

EDUCATIONAL USE ONLY. All scripts and templates are for authorized engagements only.
"""

import argparse
import textwrap
from datetime import datetime, timedelta


COLORS = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
    "dim":    "\033[90m",
}


# ─── PRETEXT TEMPLATES DATABASE ───────────────────────────────────────────────

PRETEXTS = {

    "it_helpdesk": {
        "caller_identity":  "IT Support Technician (Tier 1/2)",
        "authority_hook":   "Internal IT has access to their account data",
        "trigger_primary":  "Urgency + Authority",
        "trigger_secondary": "Fear (account disruption)",
        "target_roles":     ["employee", "manager", "executive"],

        "phone_script": """
OPENING (match their energy — formal if they sound busy, casual if relaxed):
  "Hi, this is [Name] from IT Support. I'm reaching out because our security
   monitoring flagged an issue on your account and I need to verify a few things
   quickly to prevent it being locked."

WHY IT WORKS: Authority (IT) + Fear (account locked) → they want to comply to avoid disruption.

VERIFICATION REQUEST (gets them talking, builds rapport):
  "Just to make sure I've got the right person — can you confirm you're [Name],
   working in [Department]?"
   → They confirm. You now have name + department from a 'trusted' source.

THE ASK (your actual objective):
  Option A — credential harvest:
  "We're seeing failed login attempts. I'll need you to log in now so I can check
   if the system's flagging YOUR logins as suspicious, or if it's someone else.
   What username are you seeing on your screen right now?"

  Option B — click a link:
  "I'll send you a link to our security portal to reset your credentials as a
   precaution. You'll get an email from it-support@[domain] — can you click that
   within the next 10 minutes while I have the ticket open?"

  Option C — install software (for phishing/RAT delivery):
  "We're pushing a security patch. Can you go to [URL] and run the installer?
   It'll take about 2 minutes and you won't need to reboot."

RESISTANCE HANDLER (if they push back):
  Target: "Can you email me instead?"
  You: "I would, but our system shows your email may also be compromised — that's
       why I'm calling directly. This is time-sensitive as we need to close the
       ticket in the next [15 minutes / by end of day]."

TARGET: "How do I know you're really from IT?"
  You: "Totally fair question. You can call our main IT line at [legitimate number]
       and ask for ticket #[made-up number]. Or I can have my supervisor [name]
       send you a Teams message. While I wait, I just need to..."
   → Redirect BACK to the task. Most people accept the 'I'll verify later' offer.

EXIT STRATEGY:
  "Perfect, that's all I needed. I'm closing the ticket now. You should be back
   to normal within 5 minutes. Have a good [day/afternoon]."
""",

        "email_template": """
FROM: it-support@[target-domain]
TO: [target]@[target-domain]
SUBJECT: [URGENT] Security Alert — Your Account Requires Immediate Verification

Hi [First Name],

Our security systems have detected unusual activity associated with your account.
To protect your access and prevent disruption, please verify your identity using
the link below within the next 30 minutes.

[VERIFY MY ACCOUNT] → [phishing link]

If you do not verify within 30 minutes, your account will be temporarily suspended
as a precaution while we investigate.

This is an automated security measure. If you have questions, reply to this email
or contact IT directly at [phone].

Best regards,
IT Security Team
[Company Name]
""",

        "psychological_analysis": {
            "Authority":  "Impersonating internal IT — highest trust for account-related requests",
            "Urgency":    "30-minute window + account suspension threat → they can't think clearly",
            "Fear":       "Account locked = can't work = immediate personal consequence",
            "Reciprocity":"Not used in this pretext — can be added by opening with 'I'm calling to help you'",
        },

        "quality_score": 8,
        "risk_factors": [
            "Target may call IT to verify — have a story ready",
            "IT impersonation is well-known social engineering vector — security-aware employees may suspect",
            "Email from internal domain requires phishing infrastructure or domain spoofing",
        ],
    },

    "vendor": {
        "caller_identity": "Third-party software vendor / contractor",
        "authority_hook":  "External vendors often have legitimate access to systems for support",
        "trigger_primary": "Helpfulness + Reciprocity",
        "trigger_secondary": "Authority (vendor relationship)",
        "target_roles":    ["IT admin", "developer", "sysadmin"],

        "phone_script": """
OPENING:
  "Hi [Name], this is [Name] from [Legitimate Vendor Name] — I'm working with
   [Company]'s IT team on the [software name] deployment. Is this a good moment?"

WHY IT WORKS: Vendor calls are expected. IT people are wired to help vendors succeed.
              Mentioning a known product/project name builds immediate legitimacy.

BUILD RAPPORT:
  "I've been working with [colleague name — get this from LinkedIn] on the implementation.
   I just need access to [system] for about 20 minutes to run some diagnostics."

THE ASK:
  "Would it be possible for you to create a temporary account for me? Or if it's easier,
   you could share your credentials temporarily — I can change them back after."
   → If they hesitate: "Or I could walk you through running the diagnostic yourself,
     but it's a bit technical and would take about 30 minutes of your time..."
   → Busy people will pick the easier option.

SOCIAL PROOF:
  "I was just on a call with [manager name from LinkedIn] and they approved this
   yesterday, but I don't want to bother them again for the account setup."

EXIT STRATEGY:
  "That's all I needed. I'll send you a report once the diagnostics are done.
   Thanks for the quick help — I'll let [manager name] know you sorted this out."
""",

        "email_template": """
FROM: [yourname]@[spoofed-vendor-domain]
TO: [target]
SUBJECT: Support request — [Product] diagnostics for [Company Name]

Hi [Name],

I'm following up on the support ticket #[number] we have open for [Company Name].
To complete the diagnostic, I'll need temporary VPN access or credentials for
[system/application].

I've cc'd [manager name from OSINT] who approved this scope of work.

Please let me know a convenient time for a call to coordinate access, or feel free
to share the credentials directly and I can proceed immediately.

Thanks,
[Name]
[Vendor Company] | Support Team
[phone number]
""",

        "psychological_analysis": {
            "Helpfulness": "IT staff are trained to help vendors deliver results",
            "Authority":   "Vendor relationship implies legitimate access context",
            "Social Proof": "Manager approval lowers personal responsibility for target",
            "Reciprocity": "Offering to do the work yourself pressures them to take the easier path",
        },

        "quality_score": 7,
        "risk_factors": [
            "Target may contact the real vendor to verify",
            "Technical targets (IT/devs) are more skeptical",
            "Need OSINT on actual vendor relationships first",
        ],
    },

    "recruiter": {
        "caller_identity": "External recruiter / headhunter",
        "authority_hook":  "Exclusive opportunity — appeals to self-interest",
        "trigger_primary": "Curiosity + Greed/Ambition",
        "trigger_secondary": "Flattery (liking)",
        "target_roles":    ["developer", "engineer", "analyst", "employee"],

        "phone_script": """
OBJECTIVE: This pretext gets target to open a document/link (CV template, job spec)
           or reveal internal information (org structure, tech stack, security tools).

OPENING:
  "Hi [Name], I found your profile on LinkedIn. I'm a recruiter working on a
   confidential senior role at [attractive company name]. I think you'd be a
   strong fit. Do you have 3 minutes?"

WHY IT WORKS: Everyone is interested in career opportunities, especially confidential ones.
              Flattery ("strong fit") creates instant positive feeling.

INFORMATION GATHERING (harvest internal info under cover of job interest):
  "To see if it's worth your time, can you tell me about your current tech stack?
   What security tools does your team use day-to-day?"
  → They'll share internal tech stack, security tools, infrastructure details.

  "What's the headcount on your security team? And does [Manager name] report to
   the CTO or CISO directly?"
  → Org chart information.

THE LINK:
  "I'll send you the full role description — it includes the salary band and the
   hiring company name. Could you take a look in the next hour? It's a PDF."
  → Send a PDF with macro or link to credential harvesting page.

EXIT STRATEGY:
  "I'll follow up by email with the full spec. This role is being kept confidential
   so please don't share it with colleagues — I'll be in touch within 48 hours."
""",

        "psychological_analysis": {
            "Curiosity":   "Confidential role creates need to know",
            "Flattery":    "You were 'specifically selected' — ego satisfaction",
            "Self-interest": "Better job/salary = strong personal motivation",
            "Exclusivity": "Don't tell colleagues = target feels special",
        },

        "quality_score": 9,
        "risk_factors": [
            "Target may share on social media — recruiter pretext is common and believed",
            "Technical targets may check email domain / your LinkedIn profile",
            "PDF macros are increasingly blocked by email filters",
        ],
    },

    "it_audit": {
        "caller_identity": "Internal IT Auditor / Compliance Officer",
        "authority_hook":  "Audit authority — people fear non-compliance consequences",
        "trigger_primary": "Authority + Fear of consequences",
        "trigger_secondary": "Urgency (audit deadline)",
        "target_roles":    ["employee", "IT admin", "manager"],

        "phone_script": """
OBJECTIVE: Access to systems, documents, or credentials under guise of compliance audit.

OPENING:
  "Hi [Name], I'm [Name] from Internal Audit. We're doing a scheduled compliance
   review this week for [regulation name: SOC2/ISO27001/GDPR]. I need to verify
   a few things on your system."

WHY IT WORKS: Nobody argues with an auditor. Non-compliance = personal risk for target.

THE ASK — escalating from low to high:
  Step 1 (low ask — builds compliance habit):
  "Can you confirm you've completed your annual security awareness training?
   I just need your employee ID to check the records."
  → They comply easily. You now have their employee ID.

  Step 2 (medium ask):
  "I need to verify that [policy X] is enabled on your workstation.
   Can you open [system] and take a screenshot of the [setting]?"
  → Gets them interacting with systems while you're on the call.

  Step 3 (high ask):
  "Our audit scope includes verifying admin access controls. I need to log in with
   temporary admin credentials to spot-check the configuration. Can you create a
   temporary admin account for the audit? Auditors don't share credentials."

RESISTANCE: "I need to check with my manager first."
  "Of course — just be aware the audit window closes at [today + 2 hours].
   If I can't complete the verification today, I'll need to flag [your name]
   in the audit report as non-cooperative, which triggers an escalation review.
   I'd hate for that to happen over a simple verification."

EXIT:
  "All noted. You'll get a formal audit summary from [generic audit@company email]
   within 48 hours. Thank you for your cooperation."
""",

        "psychological_analysis": {
            "Authority":   "Audit authority is near-absolute in corporate environments",
            "Fear":        "Being flagged in an audit report = personal career risk",
            "Commitment":  "Small initial compliance (employee ID) → bigger compliance later",
            "Urgency":     "Audit window closing = no time to think critically",
        },

        "quality_score": 8,
        "risk_factors": [
            "Large companies have known auditors — verify by calling the audit dept",
            "Smaller companies often suspicious of unexpected audit calls",
            "GDPR/SOX awareness training may have explicitly covered this pretext",
        ],
    },
}


def print_pretext(key: str, data: dict, company: str = "TargetCorp",
                  target_name: str = "Employee"):
    c = COLORS
    print(f"\n{c['cyan']}{c['bold']}{'═'*70}{c['reset']}")
    print(f"{c['bold']}  PRETEXT: {data['caller_identity'].upper()}{c['reset']}")
    print(f"{'═'*70}")

    print(f"\n  {c['bold']}IDENTITY:{c['reset']} {data['caller_identity']}")
    print(f"  {c['bold']}AUTHORITY HOOK:{c['reset']} {data['authority_hook']}")
    print(f"  {c['bold']}PRIMARY TRIGGER:{c['reset']} {data['trigger_primary']}")
    print(f"  {c['bold']}SECONDARY TRIGGER:{c['reset']} {data['trigger_secondary']}")
    print(f"  {c['bold']}BEST TARGET ROLES:{c['reset']} {', '.join(data['target_roles'])}")

    # Quality score bar
    score = data['quality_score']
    score_bar = "★" * score + "☆" * (10 - score)
    score_color = c["green"] if score >= 8 else (c["yellow"] if score >= 6 else c["red"])
    print(f"  {c['bold']}QUALITY SCORE:{c['reset']} {score_color}{score_bar}{c['reset']} ({score}/10)")

    # Script
    print(f"\n  {c['yellow']}{c['bold']}PHONE SCRIPT:{c['reset']}")
    script = data["phone_script"].replace("[Company Name]", company)
    script = script.replace("[target]", target_name)
    for line in script.split("\n"):
        print(f"  {line}")

    # Email template
    if "email_template" in data:
        print(f"\n  {c['yellow']}{c['bold']}EMAIL TEMPLATE:{c['reset']}")
        email = data["email_template"].replace("[Company Name]", company)
        for line in email.split("\n"):
            print(f"  {line}")

    # Psychology breakdown
    print(f"\n  {c['cyan']}{c['bold']}CIALDINI TRIGGER ANALYSIS:{c['reset']}")
    for trigger, explanation in data["psychological_analysis"].items():
        print(f"    {c['bold']}{trigger:<15}{c['reset']} {explanation}")

    # Risk factors
    print(f"\n  {c['yellow']}RISK FACTORS:{c['reset']}")
    for risk in data["risk_factors"]:
        print(f"    • {risk}")

    print(f"\n{'═'*70}\n")


def analyse_pretext():
    """Interactive pretext quality analyser."""
    c = COLORS
    print(f"\n{c['bold']}PRETEXT QUALITY ANALYSER{c['reset']}")
    print("Answer the following questions about your planned pretext:\n")

    questions = [
        ("Identity", "Is your identity believable and verifiable? (1=no, 5=yes)", 5),
        ("Authority", "Do you have a clear authority hook? (1=weak, 5=strong)", 5),
        ("Research",  "Did you OSINT the target to personalize? (1=generic, 5=personalized)", 5),
        ("Trigger",   "Do you have a clear emotional trigger (fear/urgency/curiosity)? (1=no, 5=yes)", 5),
        ("Exit",      "Do you have a clean exit strategy? (1=no, 5=yes)", 5),
        ("Recovery",  "Do you have responses for the top 3 objections? (1=no, 5=yes)", 5),
        ("Channel",   "Is the channel appropriate (phone vs email vs in-person)? (1=wrong, 5=right)", 5),
    ]

    total = 0
    for q_name, q_text, max_score in questions:
        while True:
            try:
                score_input = input(f"  {q_text}\n  Score (1-5): ").strip()
                score_val = int(score_input)
                if 1 <= score_val <= 5:
                    total += score_val
                    break
                print("  Enter 1-5")
            except (ValueError, KeyboardInterrupt):
                print()
                return

    max_total = sum(m for _, _, m in questions)
    quality   = (total / max_total) * 10

    print(f"\n  {c['bold']}Pretext quality score: {quality:.1f}/10{c['reset']}")

    if quality >= 8:
        print(f"  {c['green']}Strong pretext — proceed with confidence{c['reset']}")
    elif quality >= 6:
        print(f"  {c['yellow']}Decent pretext — review the weak areas before running{c['reset']}")
    else:
        print(f"  {c['red']}Weak pretext — significant improvement needed{c['reset']}")

    print(f"\n  Key areas to improve:")
    for q_name, q_text, max_score in questions:
        print(f"    → Review: {q_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Social engineering pretext builder with psychological analysis")
    parser.add_argument("--role", default="",
                        help=f"Pretext role. Options: {', '.join(PRETEXTS.keys())}")
    parser.add_argument("--target-role", default="employee",
                        help="Target's role (employee/manager/IT/finance etc.)")
    parser.add_argument("--company", default="TargetCorp",
                        help="Target company name for template personalization")
    parser.add_argument("--target-name", default="John",
                        help="Target person's first name")
    parser.add_argument("--list-roles", action="store_true",
                        help="List all available pretext roles")
    parser.add_argument("--analyse", action="store_true",
                        help="Interactive pretext quality analyser")
    args = parser.parse_args()

    if args.list_roles:
        print(f"\n  Available pretext roles:")
        for key, data in PRETEXTS.items():
            q = data["quality_score"]
            q_color = COLORS["green"] if q >= 8 else (COLORS["yellow"] if q >= 6 else COLORS["red"])
            print(f"    {key:<20} {q_color}★{q}/10{COLORS['reset']}  "
                  f"Best for: {', '.join(data['target_roles'][:2])}")
        return

    if args.analyse:
        analyse_pretext()
        return

    if args.role:
        key = args.role.replace("-", "_").lower()
        if key in PRETEXTS:
            print_pretext(key, PRETEXTS[key],
                         company=args.company, target_name=args.target_name)
        else:
            print(f"[-] Unknown role: {key}")
            print(f"    Available: {', '.join(PRETEXTS.keys())}")
    else:
        # show overview of all pretexts
        c = COLORS
        print(f"\n{c['bold']}SOCIAL ENGINEERING PRETEXT LIBRARY{c['reset']}")
        print(f"{c['dim']}Based on Cialdini's 6 principles of influence{c['reset']}\n")
        for key, data in PRETEXTS.items():
            q = data["quality_score"]
            q_color = c["green"] if q >= 8 else (c["yellow"] if q >= 6 else c["red"])
            print(f"  {c['bold']}{key:<20}{c['reset']} "
                  f"{q_color}★{q}/10{c['reset']}  "
                  f"{data['trigger_primary']}  →  "
                  f"Best vs {data['target_roles'][0]}")
        print(f"\n  Usage: python social_eng/pretext_builder.py --role it_helpdesk")
        print(f"         python social_eng/pretext_builder.py --analyse")


if __name__ == "__main__":
    main()
