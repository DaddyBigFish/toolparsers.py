#!/usr/bin/env python3
import os
import re
import ipaddress
import sys
import socket
from rich.console import Console
from rich.table import Table

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

def print_basic(hosts_data):
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = get_hostname(host)
        header = f"{host} {hostname}".strip()
        print(header)
        for portid, service in sorted(entries, key=lambda x: int(x[0])):
            print(f"{portid}/{service}")
        print()

def print_table(hosts_data):
    console = Console()
    table = Table(header_style="bold magenta", show_lines=True)
    table.add_column("HOST", style="cyan", no_wrap=True)
    table.add_column("PORTS", style="green")
    table.add_column("SERVICES", style="yellow")
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        entries_sorted = sorted(entries, key=lambda x: int(x[0]))
        ports_str = "\n".join(p for p, _ in entries_sorted)
        services_str = "\n".join(s for _, s in entries_sorted)
        table.add_row(host, ports_str, services_str)
    console.print(table)

def print_ips_only(hosts_data):
    for host in sorted(hosts_data.keys(), key=ipaddress.ip_address):
        hostname = get_hostname(host)
        print(f"{host} ({hostname})" if hostname else host)

if __name__ == "__main__":
    basic = "--basic" in sys.argv
    ips_only = "--ips" in sys.argv
    target_arg = None
    target_ports = None
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--basic", "--ips"):
            pass
        elif arg == "-p" and i+1 < len(sys.argv):
            target_ports = set(sys.argv[i+1].split(","))
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
    if hosts:
        if ips_only:
            print_ips_only(hosts)
        elif basic:
            print_basic(hosts)
        else:
            print_table(hosts)
