#!/usr/bin/env python3

import sys
import requests
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*",
}

def color(text, code):
    return f"\033[{code}m{text}\033[0m"

GREEN = lambda t: color(t, 32)
YELLOW = lambda t: color(t, 33)
RED = lambda t: color(t, 31)
CYAN = lambda t: color(t, 36)

def probe_url(session, url, method="GET", **kwargs):
    try:
        if method == "GET":
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False, **kwargs)
        elif method == "HEAD":
            r = session.head(url, timeout=TIMEOUT, allow_redirects=False, verify=False, **kwargs)
        elif method == "OPTIONS":
            r = session.options(url, timeout=TIMEOUT, verify=False, **kwargs)
        elif method == "PUT":
            r = session.put(url, data="pentest-test-file-123", timeout=TIMEOUT, verify=False, **kwargs)
        else:
            r = session.request(method, url, timeout=TIMEOUT, verify=False, **kwargs)
        return r
    except Exception:
        return None

def check_iis(base_url, verbose=False):
    results = []
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        print(f" {RED('[Invalid URL]')} {base_url!r}")
        return

    s = requests.Session()
    s.headers.update(HEADERS)

    # 1. Fingerprint / Server banner + ASP.NET leaks
    r = probe_url(s, base_url)
    if r:
        server = r.headers.get("Server", "").lower()
        powered = r.headers.get("X-Powered-By", "").lower()
        aspnet = r.headers.get("X-AspNet-Version", "")
        aspnetmvc = r.headers.get("X-AspNetMvc-Version", "")

        if any(x in server for x in ["iis", "microsoft-iis", "httpapi"]):
            results.append(f"{GREEN('[IIS detected]')} {server}")

        if aspnet:
            results.append(f"{YELLOW('[ASP.NET version disclosed]')} {aspnet}")
        if aspnetmvc:
            results.append(f"{YELLOW('[ASP.NET MVC version disclosed]')} {aspnetmvc}")

        if "iis" in server and re.search(r'\b(?:[6-9]|10)\.', server):
            results.append(f"{YELLOW('[IIS version exposed in banner]')}")

    # 3. Default / fingerprintable IIS/ASP pages
    defaults = ["/", "/iisstart.htm", "/welcome.png", "/default.aspx", "/aspnet_client/", "/WebResource.axd?d=", "/ScriptResource.axd?d="]
    for path in defaults:
        r_path = probe_url(s, urljoin(base_url, path))
        if r_path and r_path.status_code == 200:
            txt = r_path.text.lower()
            if any(kw in txt for kw in ["iis", "internet information services", "under construction", "welcome to iis"]):
                results.append(f"{YELLOW('[Default IIS fingerprint page]')} {path}")
            if "webresource.axd" in path.lower() and len(r_path.text) > 200 and "error" not in txt.lower():
                results.append(f"{YELLOW('[ASP.NET WebResources exposed]')} {path}")

    # 4. trace.axd – remote access check
    trace_url = urljoin(base_url, "trace.axd")
    r = probe_url(s, trace_url)
    if r and r.status_code == 200:
        text_lower = r.text.lower()
        safe_phrase = "the current trace settings prevent trace.axd from being viewed remotely"
        if safe_phrase not in text_lower:
            results.append(f"{RED('[BAD] trace.axd is remotely accessible')}")
            results.append(f" → No 'prevent ... viewed remotely' message found")
            results.append(f" URL: {trace_url}")

    # 5. Dangerous HTTP methods
    r = probe_url(s, base_url, "OPTIONS")
    if r:
        allowed = r.headers.get("Allow", "").upper()
        dav = r.headers.get("DAV", "") or r.headers.get("MS-Author-Via", "")
        danger = ["PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"]
        found = [m for m in danger if m in allowed]
        if found:
            results.append(f"{RED('[Dangerous HTTP methods allowed]')} {', '.join(found)}")
        if "DAV" in dav.upper():
            results.append(f"{RED('[WebDAV support detected]')}")

    # 6. Directory listing
    listing_probes = ["/", "/test/", "/upload/", "/backup/"]
    for p in listing_probes:
        r = probe_url(s, urljoin(base_url, p))
        if r and r.status_code == 200 and any(kw in r.text.lower() for kw in ["index of /", "directory listing", "<h1>directory"]):
            results.append(f"{RED('[Directory listing enabled]')} {p}")

    # 7. IIS 8.3 short-name (tilde) disclosure
    tilde_tests = ["~1", "a~1.aspx", "test~1*", "progra~1"]
    for t in tilde_tests:
        r = probe_url(s, urljoin(base_url, t))
        if r and r.status_code in (400, 403, 404) and any(kw in r.text for kw in ["ASP_", "IIS", "short name", "tilde"]):
            results.append(f"{YELLOW('[IIS tilde 8.3 shortname disclosure likely]')} probe={t} code={r.status_code}")

    # 8. Verbose ASP.NET errors
    bad_path = "/nonexistentfile-314159265.aspx"
    r = probe_url(s, urljoin(base_url, bad_path))
    if r and r.status_code in (500, 404) and any(kw in r.text.lower() for kw in ["server error", "yellow screen", "asp.net", "viewstate", "machinekey", "stack trace"]):
        results.append(f"{YELLOW('[Verbose ASP.NET error pages enabled]')}")

    # 9. Basic path traversal probe (non-destructive)
    trav_tests = ["../../../windows/win.ini", "..\\..\\..\\windows\\win.ini", "/%5c..%5c..%5cwindows%5cwin.ini"]
    for t in trav_tests:
        r = probe_url(s, urljoin(base_url, t))
        if r and r.status_code == 200 and any(kw in r.text for kw in ["[extensions]", "for 16-bit", "mci extensions"]):
            results.append(f"{RED('[Path traversal – win.ini readable]')} {t}")

    # Output logic – only show if there are findings (or verbose mode)
    if results:
        print(f"\n{CYAN('→ Findings on')} {base_url}")
        print("\n".join(f"  {line}" for line in results))
    elif verbose:
        print(f"\n{CYAN('→ Scanning')} {base_url}")
        print(f" {GREEN('[No high-confidence issues found]')}")

if __name__ == "__main__":
    verbose = "--verbose" in sys.argv
    if verbose:
        sys.argv.remove("--verbose")

    if len(sys.argv) != 2:
        print("Usage: python3 iis_pentest_scanner.py targets.txt [--verbose]")
        print("  --verbose : also show hosts with no issues")
        sys.exit(1)

    file_path = sys.argv[1]

    # Clean ANSI escapes + load URLs
    ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            raw_lines = f.readlines()

        urls = []
        for line in raw_lines:
            cleaned = ansi_escape.sub('', line)
            cleaned = cleaned.replace('[0m', '').replace('[m', '').replace('[34m', '').replace('[32m', '')
            cleaned = cleaned.strip()
            if cleaned and not cleaned.startswith(('#', '//')):
                if cleaned.startswith(('http://', 'https://')):
                    urls.append(cleaned)
                else:
                    print(f" Skipped non-URL line: {cleaned!r}")

        if not urls:
            print(f"{RED('No valid URLs found in file after cleaning.')}")
            sys.exit(1)

        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Loaded {len(urls)} clean URLs")

    except Exception as e:
        print(f"{RED('File read error:')} {e}")
        sys.exit(1)

    # Scan
    for url in urls:
        check_iis(url, verbose=verbose)

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan finished.")
