#!/usr/bin/env python3
import sys
import socket
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from io import StringIO

current_hostname = socket.gethostname()

filename = None
basic_mode = False
expired_mode = False
ips_mode = False
weak_mode = False
selfsigned_mode = False
selfsigned_pat1_lower = None
selfsigned_pat2_lower = None
tls_filter = None

i = 1
while i < len(sys.argv):
    arg = sys.argv[i]

    if arg in ("--basic", "-b"):
        basic_mode = True
        i += 1
        continue

    if arg in ("--expired", "-e"):
        expired_mode = True
        i += 1
        continue

    if arg in ("--ips", "-i"):
        ips_mode = True
        i += 1
        continue

    if arg in ("--weak", "-w"):
        weak_mode = True
        i += 1
        continue

    if arg == "--selfsigned":
        selfsigned_mode = True
        i += 1
        if i >= len(sys.argv):
            print("Error: --selfsigned requires at least one value", file=sys.stderr)
            sys.exit(1)

        pattern1 = sys.argv[i].strip()
        selfsigned_pat1_lower = pattern1.lower()
        i += 1

        if i < len(sys.argv) and not sys.argv[i].startswith("-"):
            pattern2 = sys.argv[i].strip()
            selfsigned_pat2_lower = pattern2.lower()
            i += 1
        else:
            selfsigned_pat2_lower = None
        continue

    if arg == "--tls":
        i += 1
        if i >= len(sys.argv):
            print("Error: --tls requires versions (comma-separated)", file=sys.stderr)
            sys.exit(1)

        values = sys.argv[i].replace(" ", "").split(",")
        tls_filter = set(v.strip() for v in values if v.strip())
        i += 1
        continue

    if filename is None:
        filename = arg
        i += 1
        continue

    print(f"Error: unexpected argument '{arg}'", file=sys.stderr)
    print("Usage: sslscan.py <xml_file> [options]", file=sys.stderr)
    print("Options:", file=sys.stderr)
    print("  -b, --basic                     Basic text output", file=sys.stderr)
    print("  -e, --expired                   Show only expired certificates", file=sys.stderr)
    print("  -i, --ips                       List only matching IP:port lines", file=sys.stderr)
    print("  -w, --weak                      Show only hosts with weak ciphers", file=sys.stderr)
    print("  --selfsigned PATTERN [PATTERN2] Filter by issuer/subject substring (case-insensitive)", file=sys.stderr)
    print("  --tls 1.0,1.1,1.2,1.3           Only show hosts supporting listed TLS versions", file=sys.stderr)
    sys.exit(1)

if filename is None:
    print("Error: missing XML filename", file=sys.stderr)
    print("Usage: sslscan.py <xml_file> [options]", file=sys.stderr)
    print("Run with --help for options", file=sys.stderr)
    sys.exit(1)

tree = None
try:
    tree = ET.parse(filename)
except FileNotFoundError:
    print(f"Error: file '{filename}' not found", file=sys.stderr)
    sys.exit(1)
except ET.ParseError as e:
    err_msg = str(e).lower()
    if any(x in err_msg for x in ["no element found", "mismatched tag", "premature end", "unexpected end"]):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read().rstrip()

            if not content.strip().endswith('</document>'):
                if content.count('<ssltest') > content.count('</ssltest>'):
                    content += '\n  </ssltest>'
                content += '\n</document>\n'

            tree = ET.parse(StringIO(content))
        except Exception as recovery_err:
            print(f"Error: XML is invalid and recovery failed: {recovery_err}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Error: invalid XML in '{filename}': {e}", file=sys.stderr)
        sys.exit(1)

if tree is None:
    sys.exit(1)

root = tree.getroot()

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def should_exclude(hostname):
    if not hostname:
        return False
    return (hostname == current_hostname or hostname.split('.')[0] == current_hostname.split('.')[0])

def has_tls_version(test):
    if not tls_filter:
        return True
    for p in test.findall("protocol"):
        if p.get("type", "").upper() == "TLS" and p.get("enabled") == "1":
            if p.get("version") in tls_filter:
                return True
    return False

def extract_sections(test):
    ip = test.get("host", "")
    port = test.get("port", "")
    sections = {}
    protos = []
    for p in test.findall("protocol"):
        typ = p.get("type", "").upper()
        ver = p.get("version", "")
        ena = "enabled" if p.get("enabled") == "1" else "disabled"
        protos.append(f"{typ}v{ver} {ena}")
    if protos:
        sections["Protocols"] = protos

    tls_filter_tlsv = {f"TLSv{v}" for v in tls_filter or []}

    ciphers = []
    for c in test.findall("cipher"):
        ver = c.get("sslversion", "")
        if tls_filter and ver not in tls_filter_tlsv:
            continue
        bits = c.get("bits", "")
        cipher = c.get("cipher", "")
        curve = f" Curve {c.get('curve','')}".strip()
        ecdhe = f" ECDHE {c.get('ecdhebits','')}".strip() if c.get("ecdhebits") else ""
        dhe = f" DHE {c.get('dhebits','')}".strip() if c.get("dhebits") else ""
        line = f"{ver} {bits} bits {cipher}{curve}{ecdhe}{dhe}".strip()
        ciphers.append(line)
    if ciphers:
        sections["Supported Ciphers"] = ciphers

    groups = []
    for g in test.findall("group"):
        ver = g.get("sslversion", "")
        if tls_filter and ver not in tls_filter_tlsv:
            continue
        bits = g.get("bits", "")
        name = g.get("name", "")
        groups.append(f"{ver} {bits} bits {name}")
    if groups:
        sections["Key Exchange Groups"] = groups

    cert_lines = []
    not_after_str = None
    issuer = None
    subject = None

    cert_node = test.find(".//certificate[@type='short']")
    if cert_node is None:
        cert_node = test.find("certificate")

    if cert_node is not None:
        sig = cert_node.find("signature-algorithm")
        if sig is not None and sig.text:
            cert_lines.append(f"Signature Algorithm: {sig.text.strip()}")
        pk = cert_node.find("pk")
        if pk is not None:
            cert_lines.append(f"RSA Key Strength: {pk.get('bits','')}")
        subj = cert_node.find("subject")
        if subj is not None and subj.text:
            subject = subj.text.strip()
            cert_lines.append(f"Subject: {subject}")
        iss = cert_node.find("issuer")
        if iss is not None and iss.text:
            issuer = iss.text.strip()
            cert_lines.append(f"Issuer: {issuer}")
        before = cert_node.find("not-valid-before")
        if before is not None and before.text:
            cert_lines.append(f"Not valid before: {before.text.strip()}")
        after = cert_node.find("not-valid-after")
        if after is not None and after.text:
            not_after_str = after.text.strip()
            cert_lines.append(f"Not valid after: {not_after_str}")

    if cert_lines:
        sections["SSL Certificate"] = cert_lines

    return ip, port, sections, not_after_str, issuer, subject

def is_expired(date_str):
    if not date_str:
        return False
    try:
        date_obj = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        date_obj = date_obj.replace(tzinfo=timezone.utc)
        return date_obj < datetime.now(timezone.utc)
    except:
        return False

def has_weak_cipher(cipher_lines):
    weak = []
    for line in cipher_lines:
        if " bits " in line:
            try:
                bits = int(line.split(" bits ")[0].split()[-1])
                if bits < 128:
                    weak.append(line)
            except:
                continue
    return weak

def matches_selfsigned(issuer, subject):
    if not selfsigned_mode:
        return True
    if not issuer and not subject:
        return False

    issuer_lower  = issuer.lower()  if issuer  else ""
    subject_lower = subject.lower() if subject else ""

    if selfsigned_pat2_lower is None:
        # single pattern → match issuer OR subject
        return selfsigned_pat1_lower in issuer_lower or selfsigned_pat1_lower in subject_lower
    else:
        # two patterns → issuer AND subject
        return selfsigned_pat1_lower in issuer_lower and selfsigned_pat2_lower in subject_lower

# ────────────────────────────────────────────────
# --ips mode (list only)
# ────────────────────────────────────────────────
if ips_mode:
    for test in root.findall("ssltest"):
        if not has_tls_version(test):
            continue
        ip, port, sections, not_after, issuer, subject = extract_sections(test)
        hostname = get_hostname(ip)
        if should_exclude(hostname):
            continue
        if expired_mode and not is_expired(not_after):
            continue
        if weak_mode and not has_weak_cipher(sections.get("Supported Ciphers", [])):
            continue
        if not matches_selfsigned(issuer, subject):
            continue

        display = f"{ip}:{port}" if port else ip
        if hostname:
            display += f" ({hostname})"
        print(display)
    sys.exit(0)

console = Console()
for test in root.findall("ssltest"):
    if not has_tls_version(test):
        continue

    ip, port, sections, not_after, issuer, subject = extract_sections(test)
    hostname = get_hostname(ip)
    if should_exclude(hostname):
        continue

    if expired_mode and not is_expired(not_after):
        continue

    weak_ciphers = None
    if weak_mode:
        weak_ciphers = has_weak_cipher(sections.get("Supported Ciphers", []))
        if not weak_ciphers:
            continue
        sections["Supported Ciphers"] = weak_ciphers

    if not matches_selfsigned(issuer, subject):
        continue

    display_ip = f"{ip}:{port}" if port else ip
    if hostname:
        display_ip += f" ({hostname})"

    if basic_mode:
        print(f"{display_ip}")
        for sec, lines in sections.items():
            if lines:
                print(f"{sec}:")
                for line in lines:
                    print(f"  {line}")
        print()
    else:
        table = Table(title="SSL Scan Results", show_lines=True)
        table.add_column("IP:Port", style="cyan", width=40)
        table.add_column("Section", style="magenta")
        table.add_column("Value", style="green")

        for sec, lines in sections.items():
            val = "\n".join(lines)
            if val.strip():
                table.add_row(display_ip, sec, val)

        console.print(table)
        print()
