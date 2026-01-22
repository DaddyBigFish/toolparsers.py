#!/usr/bin/env python3
import sys
import re
import requests
import argparse
from datetime import datetime
from urllib.parse import urljoin


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Fetch publication date of a GitHub release tag",
        add_help=True
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Full release tag URL or base repository URL"
    )
    parser.add_argument(
        "-v", "--version",
        help="Version/tag string (e.g. 6.2.6 or v7.3.9) — required if -u is repo base"
    )
    parser.add_argument(
        "-s", "--silent",
        action="store_true",
        help="Silent mode: only output the date (or nothing on error), no progress messages"
    )
    return parser.parse_args()


def generate_candidate_urls(base: str, version: str = None) -> list[str]:
    base = base.rstrip("/")

    if "/releases/tag/" in base:
        if version:
            print("[!] Warning: --version ignored when --url contains /releases/tag/", file=sys.stderr)
        return [base]

    if not version:
        print("[!] Error: --version required when --url is repo base", file=sys.stderr)
        sys.exit(1)

    candidates = []

    candidates.append(urljoin(base + "/", f"releases/tag/{version}"))

    clean_ver = version.lstrip("vV")

    if clean_ver != version:
        candidates.append(urljoin(base + "/", f"releases/tag/{clean_ver}"))

    if not version.lower().startswith("v"):
        candidates.append(urljoin(base + "/", f"releases/tag/v{clean_ver}"))

    seen = set()
    return [u for u in candidates if not (u in seen or seen.add(u))]


def fetch_release_date(urls_to_try: list[str], silent: bool = False) -> str | None:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
    }

    for url in urls_to_try:
        if not silent:
            print(f"[>] Trying → {url}", file=sys.stderr)

        try:
            resp = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
            if resp.status_code == 404:
                if not silent:
                    print("    → 404", file=sys.stderr)
                continue
            if resp.status_code != 200:
                if not silent:
                    print(f"    → HTTP {resp.status_code}", file=sys.stderr)
                continue
            resp.raise_for_status()
        except requests.RequestException as e:
            if not silent:
                print(f"    → Request failed: {e}", file=sys.stderr)
            continue

        match = re.search(r'datetime=["\']([^"\']+)["\']', resp.text)
        if not match:
            if not silent:
                print("    → No datetime found", file=sys.stderr)
            continue

        dt_raw = match.group(1)
        try:
            iso_clean = dt_raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_clean)
            if not silent:
                print(f"[✓] Found on {url}", file=sys.stderr)
            return dt.strftime("%d %B %Y")
        except ValueError as e:
            if not silent:
                print(f"    → Parse error: {e} (raw: {dt_raw})", file=sys.stderr)
            continue

    if not silent:
        print("\n[!] All attempts failed", file=sys.stderr)
        print("Tried:", file=sys.stderr)
        for u in urls_to_try:
            print(f"  • {u}", file=sys.stderr)
    return None


def main():
    args = parse_arguments()

    candidates = generate_candidate_urls(args.url, args.version)

    if not args.silent and len(candidates) > 1:
        print(f"[i] Trying {len(candidates)} tag variants...", file=sys.stderr)

    date_string = fetch_release_date(candidates, silent=args.silent)

    if date_string:
        print(date_string)
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
