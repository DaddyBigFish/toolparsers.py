#!/usr/bin/env python3
import sys
import socket
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone

current_hostname = socket.gethostname()

# Argument parsing
filename = None
basic_mode = False
expired_mode = False
ips_mode = False
weak_mode = False
selfsigned_mode = False
selfsigned_issuer = None
selfsigned_subject = None
tls_filter = None

i = 1
while i < len(sys.argv):
    arg = sys.argv[i]
    if arg == "--basic":
        basic_mode = True
    elif arg == "--expired":
        expired_mode = True
    elif arg == "--ips":
        ips_mode = True
    elif arg == "--weak":
        weak_mode = True
    elif arg == "--selfsigned":
        selfsigned_mode = True
        i += 1
        if i < len(sys.argv):
            selfsigned_issuer = sys.argv[i]
            i += 1
            if i < len(sys.argv) and not sys.argv[i].startswith("--"):
                selfsigned_subject = sys.argv[i]
            else:
                i -= 1
                selfsigned_subject = selfsigned_issuer
        else:
            print("Error: --selfsigned requires at least one value")
            sys.exit(1)
    elif arg == "--tls":
        i += 1
        if i < len(sys.argv):
            tls_filter = set(v.strip() for v in sys.argv[i].replace(" ", "").split(",") if v.strip())
        else:
            print("Error: --tls requires versions")
            sys.exit(1)
    elif filename is None:
        filename = arg
    else:
        print("Usage: sslscan.py <xml_file> [--expired] [--weak] [--basic] [--ips] [--selfsigned ISSUER [SUBJECT]] [--tls 1.0,1.1]")
        sys.exit(1)
    i += 1

if filename is None:
    print("Usage: sslscan.py <xml_file> [--expired] [--weak] [--basic] [--ips] [--selfsigned ISSUER [SUBJECT]] [--tls 1.0,1.1]")
    sys.exit(1)

try:
    tree = ET.parse(filename)
except FileNotFoundError:
    print(f"Error: file '{filename}' not found")
    sys.exit(1)
except ET.ParseError:
    print(f"Error: invalid XML in '{filename}'")
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
            cert_lines.append(f"Signature Algorithm: {sig.text}")
        pk = cert_node.find("pk")
        if pk is not None:
            cert_lines.append(f"RSA Key Strength: {pk.get('bits','')}")
        subj = cert_node.find("subject")
        if subj is not None and subj.text:
            subject = subj.text.strip()
            cert_lines.append(f"Subject: {subject}")
        alt = cert_node.find("altnames")
        if alt is not None and alt.text:
            cert_lines.append(f"Altnames: {alt.text}")
        iss = cert_node.find("issuer")
        if iss is not None and iss.text:
            issuer = iss.text.strip()
            cert_lines.append(f"Issuer: {issuer}")
        before = cert_node.find("not-valid-before")
        if before is not None and before.text:
            cert_lines.append(f"Not valid before: {before.text}")
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

# --ips mode
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
        if selfsigned_mode:
            check_i = selfsigned_issuer is None or (issuer and selfsigned_issuer in issuer)
            check_s = selfsigned_subject is None or (subject and selfsigned_subject in subject)
            if not (check_i and check_s):
                continue
        display = f"{ip}:{port}" if port else ip
        if hostname:
            display += f" ({hostname})"
        print(display)
    sys.exit(0)

# Main output
for test in root.findall("ssltest"):
    if not has_tls_version(test):
        continue
    ip, port, sections, not_after, issuer, subject = extract_sections(test)
    hostname = get_hostname(ip)
    if should_exclude(hostname):
        continue

    display_ip = f"{ip}:{port}" if port else ip
    if hostname:
        display_ip += f" ({hostname})"

    if expired_mode and not is_expired(not_after):
        continue
    if weak_mode:
        weak_ciphers = has_weak_cipher(sections.get("Supported Ciphers", []))
        if not weak_ciphers:
            continue
        sections["Supported Ciphers"] = weak_ciphers
    if selfsigned_mode:
        check_i = selfsigned_issuer is None or (issuer and selfsigned_issuer in issuer)
        check_s = selfsigned_subject is None or (subject and selfsigned_subject in subject)
        if not (check_i and check_s):
            continue

    if basic_mode:
        print(f"{display_ip}")
        for sec, lines in sections.items():
            if selfsigned_mode and sec not in ["Protocols", "SSL Certificate", "Supported Ciphers", "Key Exchange Groups"]:
                continue
            if lines:
                print(f"{sec}:")
                for line in lines:
                    print(f"  {line}")
        print()
    else:
        console = Console()
        table = Table(title="SSL Scan Results", show_lines=True)
        table.add_column("IP:Port", style="cyan", width=40)
        table.add_column("Section", style="magenta")
        table.add_column("Value", style="green")

        for sec, lines in sections.items():
            if selfsigned_mode and sec not in ["Protocols", "SSL Certificate", "Supported Ciphers", "Key Exchange Groups"]:
                continue
            val = "\n".join(lines)
            if val.strip():
                table.add_row(display_ip, sec, val)
        console.print(table)
        print()
