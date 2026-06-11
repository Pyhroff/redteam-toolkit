"""
dir_fuzzer.py — Web directory and file path fuzzer

v2 UPGRADES:
  - --proxy    : Route through Burp Suite (http://127.0.0.1:8080)
  - --jitter   : Random delay per request to evade rate-limit detection
  - --ua-rotate: Rotate User-Agent strings to blend in with real traffic
  - --recursive: Auto-fuzz discovered directories one level deep
  - --filter-size: Ignore responses of a specific byte size (filter false positives)
  - Session integration: auto-logs findings to session JSON

KILL CHAIN PHASE: Reconnaissance / Enumeration

USAGE:
  python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt
  python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt -x php,html,bak
  python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt --proxy http://127.0.0.1:8080
  python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt --jitter 0.5 --ua-rotate
  python recon/dir_fuzzer.py -u http://target.com -w wordlists/dirs.txt --recursive

WORDLIST: SecLists → Discovery/Web-Content/directory-list-2.3-small.txt
ONLY use on systems you own or have written permission to test.
"""

import requests
import argparse
import threading
import random
import time
import sys
from queue import Queue
from datetime import datetime
from pathlib import Path
import urllib3

sys.path.insert(0, str(Path(__file__).parent.parent))

# User-Agent rotation pool — makes traffic look like real browser mix
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",   # sometimes bypasses protection
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

found = []
lock = threading.Lock()
request_count = 0


def fuzz_path(base_url: str, path: str, session: requests.Session,
              valid_codes: list, timeout: int, proxies: dict,
              filter_size: int, jitter: float, ua_rotate: bool):
    """
    Send a GET request to base_url/path and record if status is interesting.
    v2: proxy support, jitter, UA rotation, size filter.
    """
    global request_count
    url = f"{base_url.rstrip('/')}/{path}"

    if ua_rotate:
        session.headers["User-Agent"] = random.choice(USER_AGENTS)
    if jitter > 0:
        time.sleep(random.uniform(0, jitter))

    try:
        resp = session.get(url, timeout=timeout, verify=False,
                           allow_redirects=False, proxies=proxies)
        with lock:
            request_count += 1
        if resp.status_code in valid_codes:
            size = len(resp.content)
            if filter_size > 0 and size == filter_size:
                return  # skip — likely false positive (same size as 404 page)
            redirect = resp.headers.get("Location", "")
            with lock:
                found.append((resp.status_code, size, url, redirect))
            redir_str = f" -> {redirect}" if redirect else ""
            # color code by status
            color = "\033[92m" if resp.status_code == 200 else (
                    "\033[93m" if resp.status_code in (301,302,307) else
                    "\033[91m" if resp.status_code in (401,403) else "\033[0m")
            reset = "\033[0m"
            print(f"  {color}[{resp.status_code}]{reset} {url:<60} ({size} bytes){redir_str}")
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass


def worker(queue: Queue, base_url: str, valid_codes: list, timeout: int,
           proxies: dict, filter_size: int, jitter: float, ua_rotate: bool):
    """Thread worker — each thread gets its own Session for performance."""
    with requests.Session() as session:
        session.headers["User-Agent"] = USER_AGENTS[0]
        while not queue.empty():
            path = queue.get()
            fuzz_path(base_url, path, session, valid_codes, timeout,
                      proxies, filter_size, jitter, ua_rotate)
            queue.task_done()


def recursive_fuzz(discovered_dirs: list, base_url: str, words: list,
                   valid_codes: list, timeout: int, proxies: dict,
                   filter_size: int, jitter: float):
    """For each discovered directory (200/301), fuzz one level deeper."""
    if not discovered_dirs:
        return
    print(f"\n[*] Recursive: fuzzing {len(discovered_dirs)} discovered directories...")
    for dir_url in discovered_dirs:
        print(f"  [>>] {dir_url}")
        q = Queue()
        for word in words[:200]:   # cap recursive at 200 words to avoid explosion
            q.put(word)
        # single-threaded recursive to avoid too much noise
        with requests.Session() as session:
            session.headers["User-Agent"] = USER_AGENTS[0]
            while not q.empty():
                path = q.get()
                fuzz_path(dir_url, path, session, valid_codes, timeout,
                          proxies, filter_size, jitter, False)
                q.task_done()


def build_paths(words: list, extensions: list) -> list:
    """Build word + word.ext variants."""
    paths = list(words)
    for word in words:
        for ext in extensions:
            paths.append(f"{word}.{ext}")
    return paths


def main():
    parser = argparse.ArgumentParser(description="Web directory/file fuzzer (v2)")
    parser.add_argument("-u", "--url", required=True, help="Base URL (e.g. http://target.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-x", "--extensions", default="",
                        help="File extensions to append (e.g. php,html,txt,bak)")
    parser.add_argument("--codes", default="200,201,301,302,307,401,403",
                        help="HTTP codes to flag (default: 200,201,301,302,307,401,403)")
    parser.add_argument("--threads", type=int, default=20, help="Thread count (default: 20)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout (default: 5s)")
    # v2 additions
    parser.add_argument("--proxy", default="",
                        help="Proxy URL for Burp (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Max random delay between requests in seconds (e.g. 0.5)")
    parser.add_argument("--ua-rotate", action="store_true",
                        help="Rotate User-Agent strings to evade WAF/rate-limiting")
    parser.add_argument("--recursive", action="store_true",
                        help="Auto-fuzz discovered directories one level deep")
    parser.add_argument("--filter-size", type=int, default=0,
                        help="Ignore responses of this exact byte size (filter false positives)")
    parser.add_argument("--session-target", default="",
                        help="Target IP/domain to auto-log findings to session file")
    args = parser.parse_args()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    try:
        with open(args.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {args.wordlist}")
        return

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]
    paths = build_paths(words, extensions)
    valid_codes = [int(c) for c in args.codes.split(",")]

    print(f"\n[*] Target   : {args.url}")
    print(f"[*] Words    : {len(words)} | Extensions: {extensions or 'none'} | Paths: {len(paths)}")
    print(f"[*] Codes    : {valid_codes}")
    print(f"[*] Threads  : {args.threads} | Jitter: {args.jitter}s | UA-rotate: {args.ua_rotate}")
    print(f"[*] Proxy    : {args.proxy or 'none'}")
    if args.filter_size:
        print(f"[*] Filter   : skipping {args.filter_size}-byte responses")
    print(f"[*] Started  : {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 70)

    q = Queue()
    for path in paths:
        q.put(path)

    threads = []
    for _ in range(min(args.threads, len(paths))):
        t = threading.Thread(target=worker,
                             args=(q, args.url, valid_codes, args.timeout,
                                   proxies, args.filter_size, args.jitter,
                                   args.ua_rotate))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    # Recursive fuzzing on discovered directories
    if args.recursive and found:
        dirs_found = [url for status, size, url, redir in found
                      if status in (200, 301) and not "." in url.split("/")[-1]]
        if dirs_found:
            recursive_fuzz(dirs_found[:5], args.url, words[:200], valid_codes,
                           args.timeout, proxies, args.filter_size, args.jitter)

    print("-" * 70)
    print(f"\n[+] {len(found)} interesting path(s) found ({request_count} requests total)")
    print(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")

    # Session logging
    if args.session_target and found:
        try:
            from core.session import Session
            s = Session.load_or_create(target=args.session_target)
            for status, size, url, redir in found:
                s.log_web_path(url, status, size)
            s.save()
            print(f"[*] Findings logged to session for {args.session_target}")
        except Exception as e:
            print(f"[!] Session logging failed: {e}")


if __name__ == "__main__":
    main()
