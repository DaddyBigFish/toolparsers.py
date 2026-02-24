#!/usr/bin/env python3
import socket
import argparse
import ipaddress
import threading
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

VERSION = "0.5"
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[33m"
ENDC = "\033[0m"

progress_lock = threading.Lock()
progress_counter = 0
total_hosts = 0

def display_banner():
    banner = rf"""{BLUE}
 _____ _____ _   _   _____  _   _  _____ _____  _   __
/  ___/  ___| | | | /  __ \| | | ||  ___/  __ \| | / /
\ `--.\ `--.| |_| | | /  \/| |_| || |__ | /  \/| |/ /
 `--. \`--. \  _  | | |    |  _  ||  __|| |    |    \
/\__/ /\__/ / | | | | \__/\| | | || |___| \__/\| |\  \
\____/\____/\_| |_/  \____/\_| |_/\____/ \____/\_| \_/
    {ENDC}
    {RED}CVE-2024-6387 Vulnerability Scan{ENDC}
"""
    print(banner)

def get_ssh_banner(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception as e:
        return None

def check_vulnerability(ip, port, timeout, result_queue):
    global progress_counter
    banner = get_ssh_banner(ip, port, timeout)

    if not banner:
        result_queue.put((ip, 'closed', 'Port closed'))
        with progress_lock:
            progress_counter += 1
        return

    if "SSH-2.0-OpenSSH" not in banner:
        result_queue.put((ip, 'unknown', f'Failed to retrieve SSH banner: {banner}'))
        with progress_lock:
            progress_counter += 1
        return

    vulnerable_versions = [
        'SSH-2.0-OpenSSH_1',
        'SSH-2.0-OpenSSH_2',
        'SSH-2.0-OpenSSH_3',
        'SSH-2.0-OpenSSH_4.0',
        'SSH-2.0-OpenSSH_4.1',
        'SSH-2.0-OpenSSH_4.2',
        'SSH-2.0-OpenSSH_4.3',
        'SSH-2.0-OpenSSH_8.5',
        'SSH-2.0-OpenSSH_8.6',
        'SSH-2.0-OpenSSH_8.7',
        'SSH-2.0-OpenSSH_8.8',
        'SSH-2.0-OpenSSH_8.9',
        'SSH-2.0-OpenSSH_9.0',
        'SSH-2.0-OpenSSH_9.1',
        'SSH-2.0-OpenSSH_9.2',
        'SSH-2.0-OpenSSH_9.3',
        'SSH-2.0-OpenSSH_9.4',
        'SSH-2.0-OpenSSH_9.5',
        'SSH-2.0-OpenSSH_9.6',
        'SSH-2.0-OpenSSH_9.7',
    ]

    excluded_versions = [
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6',
        'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
    ]

    if any(version in banner for version in vulnerable_versions) and not any(excluded in banner for excluded in excluded_versions):
        result_queue.put((ip, 'vulnerable', banner))
    else:
        result_queue.put((ip, 'not_vulnerable', f'{banner}'))

    with progress_lock:
        progress_counter += 1

def process_ip_list(ip_list_file):
    try:
        with open(ip_list_file, 'r') as file:
            ips = [line.strip() for line in file.readlines()]
        return [ip for ip in ips if ip]
    except FileNotFoundError:
        print(f"{RED}[-]{ENDC} Could not find file: {ip_list_file}")
        return []

def main():
    global total_hosts
    display_banner()
    parser = argparse.ArgumentParser(description="Check running versions of OpenSSH (CVE-2024-6387).")
    parser.add_argument("targets", nargs='*', help="IP addresses, domain names, CIDR networks, or file paths.")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0).")
    parser.add_argument("-l", "--list", help="File containing a list of IP addresses to check.")
    parser.add_argument("--port", type=int, default=22, help="Connection timeout in seconds (default: 1 second).")

    args = parser.parse_args()
    targets = args.targets
    port = args.port
    timeout = args.timeout

    ips = []

    if args.list:
        ips.extend(process_ip_list(args.list))

    for target in targets:
        try:
            with open(target, 'r') as file:
                ips.extend(file.read().splitlines())
        except IOError:
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    print(f"{RED}[-]{ENDC} Invalid CIDR notation: {target}")
            else:
                ips.append(target)

    result_queue = Queue()
    total_hosts = len(ips)

    max_workers = 100
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_vulnerability, ip, port, timeout, result_queue) for ip in ips]

        while any(future.running() for future in futures):
            with progress_lock:
                print(f"\rProgress: {progress_counter}/{total_hosts} hosts scanned", end="")
            time.sleep(0.1)

    print(f"\rProgress: {progress_counter}/{total_hosts} hosts scanned")

    total_scanned = len(ips)
    closed_ports = []
    unknown = []
    not_vulnerable = []
    vulnerable = []

    while not result_queue.empty():
        ip, status, message = result_queue.get()
        if status == 'closed':
            closed_ports += [1]
        elif status == 'unknown':
            unknown.append((ip, message))
        elif status == 'vulnerable':
            vulnerable.append((ip, message))
        else:
            not_vulnerable.append((ip, message))

    print(f"\n{BLUE}[*]{ENDC} Servers not vulnerable: {len(not_vulnerable)}")
    for ip, msg in not_vulnerable:
        print(f"{GREEN}[+]{ENDC} Server at {ip}: {msg}")
    print(f"\n{RED}[+]{ENDC} Servers likely vulnerable: {len(vulnerable)}")
    for ip, msg in vulnerable:
        print(f"{RED}[+]{ENDC} Server at {ip}: {msg}")
    print(f"\n{ORANGE}[+]{ENDC} Servers with unknown SSH Version: {len(unknown)}")
    for ip, msg in unknown:
        print(f"{ORANGE}[+]{ENDC} Server at {ip}: {msg}")
    print(f"\n{BLUE}[*]{ENDC} Servers with port {port} closed: {len(closed_ports)}")
    print(f"{BLUE}[*]{ENDC} Total scanned targets: {total_scanned}\n")

if __name__ == "__main__":
    main()
