#!/usr/bin/env python3
import os
import re
import ipaddress
import sys
import socket
from rich.console import Console
from rich.table import Table

current_hostname = socket.gethostname()

def parse_gnmap_files(target_ips=None, target_ports=None):
    hosts_data = {}
    gnmap_files = [f for f in os.listdir(".") if f.endswith(".gnmap")]
    for filename in gnmap_files:
        with open(filename, "r") as f:
            for line in f:
                if line.startswith("Host:") and "Ports:" in line:
                    parts = line.split()
                    ip = parts[1]
                    if target_ips and ip not in target_ips:
                        continue
                    ports_part = line.split("Ports:")[1].strip()
                    ports = ports_part.split(",")
                    host_ports = set()
                    has_target = False
                    for port in ports:
                        port = port.strip()
                        if not port:
                            continue
                        m = re.match(r"(\d+)/open/(\w+)//([^/]*)///?", port)
                        if m:
                            portid, proto, service = m.groups()
                            service = service if service else "unknown"
                            host_ports.add((portid, service))
                            if target_ports and portid in target_ports:
                                has_target = True
                    if target_ports and not has_target:
                        continue
                    if ip not in hosts_data:
                        hosts_data[ip] = set()
                    hosts_data[ip].update(host_ports)
    return hosts_data

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def should_exclude(hostname, exhosts):
    if not hostname:
        return False
    if hostname == current_hostname or hostname.split('.')[0] == current_hostname.split('.')[0]:
        return True
    return any(ex in hostname for ex in exhosts)

def print_basic(hosts_data, exhosts, target_ports):
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = get_hostname(host)
        if should_exclude(hostname, exhosts):
            continue
        header = f"{host} {hostname}".strip()
        print(header)
        for portid, service in sorted(entries, key=lambda x: int(x[0])):
            print(f"{portid}/{service}")
        print()

def print_table(hosts_data, exhosts):
    console = Console()
    table = Table(header_style="bold magenta", show_lines=True)
    table.add_column("HOST", style="cyan", no_wrap=True)
    table.add_column("PORTS", style="green")
    table.add_column("SERVICES", style="yellow")
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = get_hostname(host)
        if should_exclude(hostname, exhosts):
            continue
        entries_sorted = sorted(entries, key=lambda x: int(x[0]))
        ports_str = "\n".join(p for p, _ in entries_sorted)
        services_str = "\n".join(s for _, s in entries_sorted)
        table.add_row(host, ports_str, services_str)
    console.print(table)

def print_ips_only(hosts_data, exhosts, target_ports):
    for host in sorted(hosts_data.keys(), key=ipaddress.ip_address):
        hostname = get_hostname(host)
        if should_exclude(hostname, exhosts):
            continue
        if target_ports:
            open_target_ports = sorted([p for p, _ in hosts_data[host] if p in target_ports], key=int)
            if open_target_ports:
                port_str = ",".join(open_target_ports)
                out = f"{host}:{port_str}"
            else:
                out = host
        else:
            out = host
        hostname_part = f" ({hostname})" if hostname else ""
        print(out + hostname_part)

def print_allports(hosts_data, exhosts):
    lines = []
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = get_hostname(host)
        if should_exclude(hostname, exhosts):
            continue
        for portid, _ in sorted(entries, key=lambda x: int(x[0])):
            lines.append(f"{host}:{portid}")
    for line in lines:
        print(line)

if __name__ == "__main__":
    basic = "--basic" in sys.argv
    ips_only = "--ips" in sys.argv
    allports = "--allports" in sys.argv

    target_arg = None
    target_ports = None
    exhost_arg = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--basic", "--ips", "--allports"):
            pass
        elif arg == "-p" and i+1 < len(sys.argv):
            target_ports = set(sys.argv[i+1].split(","))
            i += 1
        elif arg == "--exhost" and i+1 < len(sys.argv):
            exhost_arg = sys.argv[i+1]
            i += 1
        elif not arg.startswith("-"):
            target_arg = arg
            break
        i += 1

    target_ips = None
    if target_arg:
        if os.path.isfile(target_arg):
            with open(target_arg, "r") as f:
                target_ips = {line.strip() for line in f if line.strip()}
        else:
            target_ips = {target_arg}

    hosts = parse_gnmap_files(target_ips, target_ports)

    extra_ex = [ex.strip() for ex in exhost_arg.split(",")] if exhost_arg else []
    exhosts = extra_ex

    if hosts:
        if allports:
            print_allports(hosts, exhosts)
        elif ips_only:
            print_ips_only(hosts, exhosts, target_ports)
        elif basic:
            print_basic(hosts, exhosts, target_ports)
        else:
            print_table(hosts, exhosts)
