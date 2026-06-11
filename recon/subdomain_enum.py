"""
subdomain_enum.py — DNS subdomain brute-forcer

WHY this exists:
  Companies register one domain (e.g. target.com) but have dozens of
  subdomains: dev.target.com, admin.target.com, vpn.target.com.
  These often run older, unpatched software or expose internal services.
  DNS bruteforce resolves <word>.target.com for each word in a wordlist —
  if it resolves, the subdomain exists.

TECHNIQUE: Active DNS enumeration (makes real DNS queries — not passive).
KILL CHAIN PHASE: Reconnaissance

USAGE:
  python subdomain_enum.py -d target.com -w wordlists/subdomains.txt
  python subdomain_enum.py -d target.com -w wordlists/subdomains.txt --threads 50

WORDLIST SUGGESTION: SecLists → Discovery/DNS/subdomains-top1million-5000.txt
                     https://github.com/danielmiessler/SecLists

ONLY use on domains you own or have written permission to test.
"""

import dns.resolver
import argparse
import threading
from queue import Queue
from datetime import datetime

found = []
lock = threading.Lock()


def resolve_subdomain(subdomain: str, domain: str, resolver: dns.resolver.Resolver):
    """
    Try to resolve <subdomain>.<domain> via DNS A record lookup.
    A successful resolve = subdomain exists and points somewhere.
    """
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answers]
        with lock:
            found.append((fqdn, ips))
        print(f"  [+] {fqdn:<45} -> {', '.join(ips)}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception:
        pass


def worker(queue: Queue, domain: str):
    """Thread worker — resolves subdomains from the queue."""
    # each thread gets its own resolver to avoid contention
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    # use public DNS servers for faster resolution
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

    while not queue.empty():
        subdomain = queue.get()
        resolve_subdomain(subdomain, domain, resolver)
        queue.task_done()


def main():
    parser = argparse.ArgumentParser(description="DNS subdomain brute-forcer")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to subdomain wordlist")
    parser.add_argument("--threads", type=int, default=30, help="Thread count (default: 30)")
    args = parser.parse_args()

    try:
        with open(args.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {args.wordlist}")
        return

    print(f"\n[*] Target domain : {args.domain}")
    print(f"[*] Wordlist       : {len(words)} words")
    print(f"[*] Threads        : {args.threads}")
    print(f"[*] Started        : {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 60)

    q = Queue()
    for word in words:
        q.put(word)

    threads = []
    for _ in range(min(args.threads, len(words))):
        t = threading.Thread(target=worker, args=(q, args.domain))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    print("-" * 60)
    print(f"\n[+] {len(found)} subdomain(s) discovered")
    print(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")

    if found:
        print("\n--- RESULTS ---")
        for fqdn, ips in sorted(found):
            print(f"  {fqdn} -> {', '.join(ips)}")


if __name__ == "__main__":
    main()
