#!/usr/bin/env python3
import sys
import socket
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone

if len(sys.argv) < 2:
    print("Usage: python3 sslscan.py <xml_file> [--basic] [--expired] [--ips]")
    sys.exit(1)

filename = sys.argv[1]
basic_mode = "--basic" in sys.argv
expired_mode = "--expired" in sys.argv
ips_mode = "--ips" in sys.argv

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

def extract_sections(test):
    ip = test.get("host", "")
    sections = {}

    # Protocols
    protos = []
    for p in test.findall("protocol"):
        typ = p.get("type", "").upper()
        ver = p.get("version", "")
        ena = "enabled" if p.get("enabled") == "1" else "disabled"
        protos.append(f"{typ}v{ver} {ena}")
    if protos:
        sections["Protocols"] = protos

    # Fallback
    if (fb := test.find("fallback")) is not None:
        sections["Fallback SCSV"] = ["supported" if fb.get("supported") == "1" else "not supported"]

    # Renegotiation
    if (reneg := test.find("renegotiation")) is not None:
        supp = "supported" if reneg.get("supported") == "1" else "not supported"
        sec = "secure" if reneg.get("secure") == "1" else "insecure"
        sections["Renegotiation"] = [f"{supp}, {sec}"]

    # Compression
    if (comp := test.find("compression")) is not None:
        sections["Compression"] = ["supported" if comp.get("supported") == "1" else "disabled"]

    # Heartbleed
    hb_lines = []
    for hb in test.findall("heartbleed"):
        ver = hb.get("sslversion")
        vul = "vulnerable" if hb.get("vulnerable") == "1" else "not vulnerable"
        hb_lines.append(f"{ver} {vul}")
    if hb_lines:
        sections["Heartbleed"] = hb_lines

    # Ciphers
    ciphers = []
    for c in test.findall("cipher"):
        ver = c.get("sslversion", "")
        bits = c.get("bits", "")
        cipher = c.get("cipher", "")
        curve = f" Curve {c.get('curve','')}".strip()
        ecdhe = f" DHE {c.get('ecdhebits','')}".strip() if c.get("ecdhebits") else ""
        dhe = f" DHE {c.get('dhebits','')}".strip() if c.get("dhebits") else ""
        line = f"{ver} {bits} bits {cipher}{curve}{ecdhe}{dhe}".strip()
        ciphers.append(line)
    if ciphers:
        sections["Supported Ciphers"] = ciphers

    # Groups
    groups = []
    for g in test.findall("group"):
        ver = g.get("sslversion", "")
        bits = g.get("bits", "")
        name = g.get("name", "")
        groups.append(f"{ver} {bits} bits {name}")
    if groups:
        sections["Key Exchange Groups"] = groups

    # Certificate
    cert_lines = []
    not_after_str = None
    if (certs := test.find("certificates")) is not None:
        cert = certs.find("certificate")
        if cert is not None:
            sig = cert.find("signature-algorithm")
            if sig is not None and sig.text:
                cert_lines.append(f"Signature Algorithm: {sig.text}")
            pk = cert.find("pk")
            if pk is not None:
                cert_lines.append(f"RSA Key Strength: {pk.get('bits','')}")
            subj = cert.find("subject")
            if subj is not None and subj.text:
                cert_lines.append(f"Subject: {subj.text}")
            alt = cert.find("altnames")
            if alt is not None and alt.text:
                cert_lines.append(f"Altnames: {alt.text}")
            iss = cert.find("issuer")
            if iss is not None and iss.text:
                cert_lines.append(f"Issuer: {iss.text}")
            before = cert.find("not-valid-before")
            if before is not None and before.text:
                cert_lines.append(f"Not valid before: {before.text}")
            after = cert.find("not-valid-after")
            if after is not None and after.text:
                not_after_str = after.text.strip()
                cert_lines.append(f"Not valid after: {not_after_str}")
    if cert_lines:
        sections["SSL Certificate"] = cert_lines

    return ip, sections, not_after_str

def is_expired(date_str):
    if not date_str:
        return False
    try:
        date_obj = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        date_obj = date_obj.replace(tzinfo=timezone.utc)
        return date_obj < datetime.now(timezone.utc)
    except:
        return False

# --ips mode: just list IP:port (hostname)
if ips_mode:
    for test in root.findall("ssltest"):
        ip = test.get("host", "")
        xml_port = test.get("port", "")
        if expired_mode:
            _, _, not_after = extract_sections(test)
            if not is_expired(not_after):
                continue
        hostname = get_hostname(ip)
        display = f"{ip}:{xml_port}" if xml_port else ip
        if hostname:
            display += f" ({hostname})"
        print(display)
    sys.exit(0)

# Normal modes
if basic_mode:
    for test in root.findall("ssltest"):
        ip, sections, not_after = extract_sections(test)
        hostname = get_hostname(ip)
        display_ip = f"{ip} ({hostname})" if hostname else ip

        if expired_mode:
            if not is_expired(not_after):
                continue
            print(f"{display_ip}")
            print("SSL Certificate:")
            for line in sections.get("SSL Certificate", []):
                print(line)
            print()
        else:
            print(f"{display_ip}")
            for sec, lines in sections.items():
                print(f"{sec}:")
                for line in lines:
                    print(line)
            print()
else:
    console = Console()
    table = Table(title="SSL Scan Results", show_lines=True)
    table.add_column("IP", style="cyan", width=30)
    table.add_column("Section", style="magenta")
    table.add_column("Value", style="green")

    for test in root.findall("ssltest"):
        ip, sections, not_after = extract_sections(test)
        hostname = get_hostname(ip)
        display_ip = f"{ip} ({hostname})" if hostname else ip

        if expired_mode:
            if not is_expired(not_after):
                continue
            cert_val = "\n".join(sections.get("SSL Certificate", []))
            if cert_val:
                table.add_row(display_ip, "SSL Certificate", cert_val)
        else:
            for sec, lines in sections.items():
                val = "\n".join(lines)
                table.add_row(display_ip, sec, val)

    console.print(table)
