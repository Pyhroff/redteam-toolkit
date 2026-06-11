"""
utils/smart_passwords.py — OSINT-aware target-specific password generator

WHY GENERIC ROCKYOU FAILS ON REAL TARGETS:
  Rockyou has 14M passwords. But a real IT admin at "AcmeCorp" is most
  likely using something like: AcmeCorp2024! or admin@acme or Acme#1234.
  Generic wordlists don't have these. This script generates them.

  The idea: take what you know about the target from OSINT and generate
  passwords using the patterns real humans follow when creating passwords.

PATTERNS HUMANS USE (backed by research):
  1. Company name + year + special char       → Acme2024!
  2. Username variations                       → john.doe, johndoe, jdoe
  3. First/Last name + birthday               → john1990, doe1990@
  4. Department + year                        → itsupport2023
  5. Keyboard walks                           → qwerty123, 1q2w3e4r
  6. Leet speak                               → p@$$word, 4dm1n
  7. Season + year                            → Winter2024!, Spring2023
  8. City/location + numbers                  → Mumbai123, delhi@2024
  9. Pet/child name (from LinkedIn/social)     → charlie2020, labrador!
  10. Common service defaults                 → admin/password/changeme

USAGE:
  python utils/smart_passwords.py --company "AcmeCorp" --domain "acmecorp.com"
  python utils/smart_passwords.py --name "John Doe" --username "jdoe"
  python utils/smart_passwords.py --company Acme --name "John" --year 2023 --output wordlist.txt
  python utils/smart_passwords.py --full-context (interactive mode)

OUTPUT: A deduplicated wordlist you feed into ssh_brute.py or hashcat.
"""

import argparse
import itertools
from datetime import datetime
from pathlib import Path


LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
}

SPECIAL_CHARS  = ["!", "@", "#", "$", ".", "_", "-", "*"]
CURRENT_YEAR   = datetime.now().year
YEARS          = [str(y) for y in range(CURRENT_YEAR - 4, CURRENT_YEAR + 2)]
SEASONS        = ["Spring", "Summer", "Autumn", "Winter", "Fall"]
COMMON_SUFFIXES= ["123", "1234", "12345", "!", "!!", "@123", "#1", "123!", "321"]

# Default + service credentials often left unchanged
DEFAULT_CREDS  = [
    "admin", "password", "Password", "password1", "Password1",
    "changeme", "changeme123", "letmein", "letmein123",
    "Welcome1", "Welcome123", "welcome1", "12345678",
    "qwerty", "qwerty123", "Qwerty123!",
    "root", "toor", "user", "user123",
    "admin123", "admin@123", "Admin123!",
    "test", "test123", "Test@123",
    "pass", "pass123", "P@ssw0rd", "P@$$w0rd",
    "master", "dragon", "monkey",
]

KEYBOARD_WALKS = [
    "qwerty", "qwerty123", "qwertyuiop",
    "asdfgh", "asdfghjkl", "asdf1234",
    "zxcvbn", "zxcvbnm",
    "1q2w3e", "1q2w3e4r", "1q2w3e4r5t",
    "q1w2e3r4", "!qaz2wsx", "!QAZ2wsx",
    "qazsedcftgbvhy", "qazwsx", "!@#$qwer",
    "123qwe", "123456", "654321",
    "abc123", "abc@123", "Abc@123",
]


def leet_variants(word: str, max_variants: int = 4) -> list:
    """
    Generate leet-speak variants of a word.
    E.g. "password" → "p@ssword", "p@$$word", "passw0rd"
    Limited to avoid combinatorial explosion.
    """
    variants = {word}
    for char, replacements in LEET_MAP.items():
        if char in word.lower():
            for rep in replacements:
                new = word.lower().replace(char, rep)
                variants.add(new)
                variants.add(new.capitalize())
    return list(variants)[:max_variants]


def case_variants(word: str) -> list:
    """Generate case variations."""
    return list({
        word, word.lower(), word.upper(), word.capitalize(),
        word[0].upper() + word[1:].lower() if len(word) > 1 else word,
    })


def generate_company_passwords(company: str) -> list:
    """Generate company-name-based passwords using common enterprise patterns."""
    words = []
    variants = case_variants(company)
    # strip spaces and common suffixes from company name
    clean = company.replace(" ", "").replace("Corp", "").replace("Inc", "").replace("Ltd", "")
    clean_variants = case_variants(clean)
    all_variants = variants + clean_variants

    for var in all_variants:
        # + year
        for year in YEARS:
            words.append(f"{var}{year}")
            words.append(f"{var}@{year}")
            words.append(f"{var}{year}!")
            words.append(f"{var}#{year}")

        # + special + number
        for suffix in COMMON_SUFFIXES:
            words.append(f"{var}{suffix}")

        # seasonal
        for season in SEASONS:
            words.append(f"{season}{var}")
            words.append(f"{var}{season}")
            words.append(f"{season}{var}{YEARS[-1]}!")

        # + @ (very common in corporate passwords)
        words.append(f"{var}@1")
        words.append(f"{var}@123")
        words.append(f"{var}#1")

        # leet variants
        words.extend(leet_variants(var))

    return words


def generate_name_passwords(first: str = "", last: str = "",
                            username: str = "", birthday: str = "") -> list:
    """Generate personal-name-based passwords."""
    words = []

    # derive username variants if not provided
    usernames = set()
    if username:
        usernames.add(username.lower())
    if first and last:
        f, l = first.lower(), last.lower()
        usernames.update([
            f"{f}{l}", f"{f}.{l}", f"{f[0]}{l}", f"{f}{l[0]}",
            f"{l}{f}", f"{l}.{f}", f"{l}{f[0]}",
            f"{f}", f"{l}",
        ])
    elif first:
        usernames.add(first.lower())

    year_variants = [birthday[:4]] if birthday else YEARS

    for uname in usernames:
        for year in year_variants:
            words.append(f"{uname}{year}")
            words.append(f"{uname}@{year}")
            words.append(f"{uname}{year}!")

        for suffix in COMMON_SUFFIXES:
            words.append(f"{uname}{suffix}")

        words.extend(case_variants(uname))
        words.extend(leet_variants(uname))

        # capitalize + special
        words.append(f"{uname.capitalize()}!")
        words.append(f"{uname.capitalize()}@1")
        words.append(f"{uname.capitalize()}123!")

    return words


def generate_domain_passwords(domain: str) -> list:
    """Extract domain name part and generate variants."""
    # "acmecorp.com" → "acmecorp"
    domain_name = domain.split(".")[0] if "." in domain else domain
    return generate_company_passwords(domain_name)


def generate_contextual(context_list: list) -> list:
    """
    Generic: take any list of words (team names, pet names, city, project name)
    and generate password variants.
    """
    words = []
    for word in context_list:
        words.extend(case_variants(word))
        words.extend(leet_variants(word))
        for year in YEARS:
            words.append(f"{word}{year}")
            words.append(f"{word.capitalize()}{year}!")
        for suffix in COMMON_SUFFIXES:
            words.append(f"{word}{suffix}")
            words.append(f"{word.capitalize()}{suffix}")
    return words


def deduplicate_and_filter(wordlist: list, min_len: int = 6, max_len: int = 30) -> list:
    """Remove duplicates, filter by length."""
    seen = set()
    result = []
    for word in wordlist:
        w = word.strip()
        if w and w not in seen and min_len <= len(w) <= max_len:
            seen.add(w)
            result.append(w)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="OSINT-aware target-specific password generator")
    parser.add_argument("--company",  default="", help="Company/organization name")
    parser.add_argument("--domain",   default="", help="Target domain (e.g. acme.com)")
    parser.add_argument("--name",     default="", help="Target person's name (First Last)")
    parser.add_argument("--username", default="", help="Known username")
    parser.add_argument("--birthday", default="",
                        help="Birthday (YYYYMMDD or YYYY)")
    parser.add_argument("--context",  default="",
                        help="Comma-separated extra context words (pet,city,team,project)")
    parser.add_argument("--year",     type=int, default=0,
                        help="Specific year to prioritize")
    parser.add_argument("--output",   default="",
                        help="Output file (default: stdout)")
    parser.add_argument("--no-defaults", action="store_true",
                        help="Skip generic default credentials")
    parser.add_argument("--min-len",  type=int, default=6, help="Minimum password length")
    parser.add_argument("--max-len",  type=int, default=30, help="Maximum password length")
    args = parser.parse_args()

    all_words = []

    # generic defaults (always useful)
    if not args.no_defaults:
        all_words.extend(DEFAULT_CREDS)
        all_words.extend(KEYBOARD_WALKS)

    # company-based
    if args.company:
        all_words.extend(generate_company_passwords(args.company))

    # domain-based
    if args.domain:
        all_words.extend(generate_domain_passwords(args.domain))

    # name-based
    if args.name:
        parts = args.name.split(maxsplit=1)
        first = parts[0] if parts else ""
        last  = parts[1] if len(parts) > 1 else ""
        all_words.extend(generate_name_passwords(
            first=first, last=last,
            username=args.username, birthday=args.birthday
        ))
    elif args.username:
        all_words.extend(generate_name_passwords(username=args.username,
                                                  birthday=args.birthday))

    # seasonal + year
    if args.year:
        for season in SEASONS:
            for suffix in ["", "!", "@123", "123"]:
                all_words.append(f"{season}{args.year}{suffix}")
        if args.company:
            for suffix in ["!", "@123", "123!"]:
                all_words.append(f"{args.company.capitalize()}{args.year}{suffix}")

    # extra context words
    if args.context:
        context_words = [w.strip() for w in args.context.split(",") if w.strip()]
        all_words.extend(generate_contextual(context_words))

    # cross-combine company + name (e.g. AcmeJohn2024)
    if args.company and args.name:
        first = args.name.split()[0]
        clean_co = args.company.replace(" ", "")
        for year in YEARS[-3:]:
            all_words.append(f"{clean_co}{first}{year}")
            all_words.append(f"{first}{clean_co}{year}!")

    # dedup
    final = deduplicate_and_filter(all_words, args.min_len, args.max_len)

    print(f"\n[*] Generated {len(final)} unique passwords", flush=True)
    print(f"    Context: company={args.company!r} name={args.name!r} "
          f"username={args.username!r} domain={args.domain!r}")

    if args.output:
        Path(args.output).write_text("\n".join(final) + "\n")
        print(f"[+] Saved to: {args.output}")
        print(f"\n    Use with:")
        print(f"    python exploitation/ssh_brute.py -t <target> -u <user> -w {args.output}")
        print(f"    hashcat -m 0 hash.txt {args.output}")
    else:
        print()
        for word in final:
            print(word)


if __name__ == "__main__":
    main()
