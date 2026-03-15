#!/usr/bin/env python3

import socket
import os
import sys
import re
import json
import struct
import http.client
import threading
import ipaddress
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pyfiglet
except ImportError:
    print("Missing required package: pyfiglet")
    print("Install it with: pip install pyfiglet")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Missing required package: tqdm")
    print("Install it with: pip install tqdm")
    sys.exit(1)

lock = threading.Lock()

CIDR_REGEX = re.compile(r'["\']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})["\']?')
IP_REGEX = re.compile(r'["\']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']?')


def print_banner():
    banner = pyfiglet.figlet_format("ReverseDNS", font="slant")
    print("\033[96m" + banner + "\033[0m")
    print("\033[93m  Reverse DNS IP Lookup Tool\033[0m")
    print("\033[90m  Resolve IPs, CIDR blocks, and IP lists\033[0m")
    print("\033[90m  back to domain names in bulk.\033[0m")
    print()
    print("\033[90m  ─────────────────────────────────────────────\033[0m")
    print()


def print_success(msg):
    print(f"\033[92m  [+] {msg}\033[0m")


def print_info(msg):
    print(f"\033[94m  [*] {msg}\033[0m")


def print_warn(msg):
    print(f"\033[93m  [!] {msg}\033[0m")


def print_error(msg):
    print(f"\033[91m  [-] {msg}\033[0m")


def print_header(msg):
    print(f"\n\033[96m  [{msg}]\033[0m")


def print_divider():
    print("\033[90m  ─────────────────────────────────────────────\033[0m")


def https_get(host, path, timeout=5):
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        conn.request("GET", path, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
        })
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return resp.status, data
    except Exception:
        return None, ""


def create_output_folder(label):
    safe_label = re.sub(r'[^\w\-.]', '_', label)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = os.path.join("reverse-dns-results", f"{safe_label}_{timestamp}")
    os.makedirs(folder, exist_ok=True)
    return folder


def append_result(folder, filename, line):
    filepath = os.path.join(folder, filename)
    with lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def parse_ips_from_input(raw_input):
    ips = set()

    cidrs = CIDR_REGEX.findall(raw_input)
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                ips.add(str(ip))
        except ValueError:
            pass

    remaining = CIDR_REGEX.sub('', raw_input)
    single_ips = IP_REGEX.findall(remaining)
    for ip in single_ips:
        try:
            ipaddress.ip_address(ip)
            ips.add(ip)
        except ValueError:
            pass

    return sorted(ips, key=lambda x: tuple(int(p) for p in x.split('.')))


def parse_ips_from_file(filepath):
    ips = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print_error(f"File not found: {filepath}")
        return []
    except PermissionError:
        print_error(f"Permission denied: {filepath}")
        return []

    cidrs = CIDR_REGEX.findall(content)
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                ips.add(str(ip))
        except ValueError:
            pass

    remaining = CIDR_REGEX.sub('', content)
    single_ips = IP_REGEX.findall(remaining)
    for ip in single_ips:
        try:
            ipaddress.ip_address(ip)
            ips.add(ip)
        except ValueError:
            pass

    return sorted(ips, key=lambda x: tuple(int(p) for p in x.split('.')))


def reverse_ptr(ip):
    try:
        socket.setdefaulttimeout(3)
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        all_names = [hostname] + list(aliases)
        return list(set(all_names))
    except (socket.herror, socket.gaierror, OSError, socket.timeout):
        return []


def reverse_rapiddns(ip):
    domains = set()
    try:
        status, data = https_get("rapiddns.io", f"/s/{ip}?full=1")
        if status == 200 and data:
            pattern = r'<td>([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,})</td>'
            matches = re.findall(pattern, data)
            for m in matches:
                domains.add(m.lower())
    except Exception:
        pass
    return sorted(domains)


def reverse_hackertarget(ip):
    domains = set()
    try:
        status, data = https_get("api.hackertarget.com", f"/reverseiplookup/?q={ip}")
        if status == 200 and data:
            if "error" not in data.lower() and "no records" not in data.lower() and "API count" not in data:
                for line in data.strip().split("\n"):
                    line = line.strip()
                    if line and re.match(r'^[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}$', line):
                        domains.add(line.lower())
    except Exception:
        pass
    return sorted(domains)


def lookup_single_ip(ip, methods, folder):
    all_domains = set()
    ptr_names = []

    if "ptr" in methods:
        ptr_names = reverse_ptr(ip)
        all_domains.update(ptr_names)

    if "rapiddns" in methods:
        rapid_results = reverse_rapiddns(ip)
        all_domains.update(rapid_results)

    if "hackertarget" in methods:
        ht_results = reverse_hackertarget(ip)
        all_domains.update(ht_results)

    if all_domains:
        for domain in sorted(all_domains):
            append_result(folder, "domains.txt", domain)

        with lock:
            append_result(folder, "ips_with_domains.txt", ip)

        return ip, sorted(all_domains)
    else:
        append_result(folder, "ips_no_results.txt", ip)
        return ip, []


def select_methods(ip_count=0):
    print_header("Lookup Methods")
    print()
    print("    1) PTR records only (fastest, ~1000+ IPs/sec)")
    print("    2) PTR + RapidDNS (slower, HTTP request per IP)")
    print("    3) PTR + HackerTarget (slower, HTTP request per IP)")
    print("    4) PTR + RapidDNS + HackerTarget (slowest, 2 HTTP requests per IP)")
    print("    5) RapidDNS + HackerTarget (skip PTR)")
    print()

    if ip_count > 10000:
        print_warn(f"You have {ip_count:,} IPs. Methods 2-5 make HTTP requests per IP.")
        print_warn(f"Method 2 = {ip_count:,} HTTP requests. Method 4 = {ip_count * 2:,} HTTP requests.")
        print_warn("For large scans, PTR only (option 1) is strongly recommended.")
        print()

    default = "1" if ip_count > 50000 else "4"
    choice = input(f"\033[97m  Choose methods [1-5, default {default}]: \033[0m").strip() or default

    method_map = {
        "1": ["ptr"],
        "2": ["ptr", "rapiddns"],
        "3": ["ptr", "hackertarget"],
        "4": ["ptr", "rapiddns", "hackertarget"],
        "5": ["rapiddns", "hackertarget"],
    }

    methods = method_map.get(choice, method_map[default])

    if ip_count > 10000 and any(m in methods for m in ["rapiddns", "hackertarget"]):
        api_count = sum(1 for m in methods if m in ["rapiddns", "hackertarget"])
        total_requests = ip_count * api_count
        est_minutes = total_requests / 60
        print_warn(f"This will make ~{total_requests:,} HTTP requests (~{est_minutes:,.0f} minutes minimum).")
        confirm = input("\033[97m  Are you sure? [y/N]: \033[0m").strip().lower()
        if confirm != "y":
            print_info("Switched to PTR only.")
            methods = ["ptr"]

    print_info(f"Using methods: {', '.join(methods)}")
    return methods


def select_threads(ip_count=0):
    if ip_count > 100000:
        default_threads = 100
    elif ip_count > 10000:
        default_threads = 50
    else:
        default_threads = 20

    threads_str = input(f"\033[97m  Concurrent threads [{default_threads}]: \033[0m").strip() or str(default_threads)
    try:
        threads = int(threads_str)
        if threads < 1:
            threads = 1
        if threads > 500:
            print_warn("Capping at 500 threads.")
            threads = 500
    except ValueError:
        threads = default_threads
    return threads


def run_scan(ips, methods, threads, label):
    if not ips:
        print_error("No valid IPs to scan.")
        return

    folder = create_output_folder(label)

    ptr_only = methods == ["ptr"]
    if ptr_only:
        rate_est = threads * 50
    else:
        api_count = sum(1 for m in methods if m in ["rapiddns", "hackertarget"])
        rate_est = threads * (2 if api_count == 0 else 0.5 / api_count)
    est_seconds = len(ips) / max(rate_est, 1)
    if est_seconds < 60:
        eta_str = f"~{int(est_seconds)}s"
    elif est_seconds < 3600:
        eta_str = f"~{int(est_seconds / 60)}m {int(est_seconds % 60)}s"
    else:
        hours = int(est_seconds / 3600)
        mins_left = int((est_seconds % 3600) / 60)
        eta_str = f"~{hours}h {mins_left}m"

    print()
    print_divider()
    print_header("Scan Configuration")
    print_info(f"IPs to scan:   {len(ips):,}")
    print_info(f"Methods:       {', '.join(methods)}")
    print_info(f"Threads:       {threads}")
    print_info(f"Est. time:     {eta_str}")
    print_info(f"Output folder: {folder}")
    print_divider()
    print()

    append_result(folder, "scan_info.txt", f"Scan started: {datetime.now().isoformat()}")
    append_result(folder, "scan_info.txt", f"Total IPs: {len(ips)}")
    append_result(folder, "scan_info.txt", f"Methods: {', '.join(methods)}")
    append_result(folder, "scan_info.txt", f"Threads: {threads}")

    total_domains = 0
    ips_with_results = 0
    ips_without_results = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(lookup_single_ip, ip, methods, folder): ip for ip in ips}

        pbar = tqdm(
            total=len(ips),
            desc="  Scanning",
            unit="ip",
            bar_format="  {l_bar}{bar:40}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
            ncols=100,
            file=sys.stderr,
        )
        for future in as_completed(futures):
            ip, domains = future.result()
            if domains:
                ips_with_results += 1
                total_domains += len(domains)
                for d in domains:
                    tqdm.write(f"\033[92m  [+] {d}\033[0m")
            else:
                ips_without_results += 1
            pbar.update(1)
        pbar.close()

    elapsed = time.time() - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    all_domains = set()
    domains_file = os.path.join(folder, "domains.txt")
    if os.path.exists(domains_file):
        with open(domains_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    all_domains.add(line)

    unique_domains = len(all_domains)

    print()
    print_divider()
    print_header("Scan Results")
    print_success(f"IPs scanned:      {len(ips):,}")
    print_success(f"IPs with domains: {ips_with_results:,}")
    print_error(f"IPs no results:   {ips_without_results:,}")
    print_info(f"Total domains:    {total_domains:,}")
    print_info(f"Unique domains:   {unique_domains:,}")
    print_info(f"Time elapsed:     {mins}m {secs}s")
    if elapsed > 0:
        print_info(f"Speed:            {len(ips) / elapsed:.1f} IPs/sec")

    hit_rate = (ips_with_results / len(ips) * 100) if ips else 0
    print_info(f"Hit rate:         {hit_rate:.1f}%")
    print_divider()

    append_result(folder, "scan_info.txt", f"Scan completed: {datetime.now().isoformat()}")
    append_result(folder, "scan_info.txt", f"IPs with domains: {ips_with_results}")
    append_result(folder, "scan_info.txt", f"IPs no results: {ips_without_results}")
    append_result(folder, "scan_info.txt", f"Total domains found: {total_domains}")
    append_result(folder, "scan_info.txt", f"Unique domains: {unique_domains}")
    append_result(folder, "scan_info.txt", f"Elapsed: {mins}m {secs}s")

    if unique_domains > 0:
        sorted_domains_file = os.path.join(folder, "domains_sorted.txt")
        with open(sorted_domains_file, "w") as f:
            for d in sorted(all_domains):
                f.write(d + "\n")

    print()
    print_success(f"All results saved to: {folder}/")
    print_info("Files:")
    for fname in sorted(os.listdir(folder)):
        fpath = os.path.join(folder, fname)
        size = os.path.getsize(fpath)
        if size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        print(f"\033[90m    {fname:<30} {size_str}\033[0m")

    if unique_domains > 0 and unique_domains <= 50:
        print()
        print_header("Domains Found")
        for d in sorted(all_domains):
            print(f"\033[92m    {d}\033[0m")


def mode_single_ip():
    print_header("Single IP Lookup")
    ip_input = input("\n\033[97m  Enter IP address: \033[0m").strip()
    if not ip_input:
        print_error("No IP entered.")
        return

    ips = parse_ips_from_input(ip_input)
    if not ips:
        print_error(f"Invalid IP address: {ip_input}")
        return

    print_info(f"Target: {ips[0]}")
    methods = select_methods(ip_count=len(ips))
    threads = 1
    run_scan(ips, methods, threads, ips[0])


def mode_multiple_ips():
    print_header("Multiple IP Lookup")
    print()
    print_info("Enter IPs separated by commas, spaces, or in [x.x.x.x, x.x.x.x] format.")
    print_info("You can also mix IPs with CIDR blocks.")
    print()

    ip_input = input("\033[97m  Enter IPs/CIDRs: \033[0m").strip()
    if not ip_input:
        print_error("No input provided.")
        return

    ips = parse_ips_from_input(ip_input)
    if not ips:
        print_error("No valid IPs found in input.")
        return

    print_success(f"Parsed {len(ips):,} IP(s)")

    if len(ips) <= 10:
        for ip in ips:
            print(f"\033[90m    {ip}\033[0m")
    else:
        for ip in ips[:5]:
            print(f"\033[90m    {ip}\033[0m")
        print(f"\033[90m    ... and {len(ips) - 5:,} more\033[0m")

    methods = select_methods(ip_count=len(ips))
    threads = select_threads(ip_count=len(ips))
    run_scan(ips, methods, threads, "multi_ip")


def mode_cidr():
    print_header("CIDR Block Lookup")
    print()
    print_info("Enter one or more CIDR blocks (e.g. 192.168.1.0/24, 10.0.0.0/28).")
    print()

    cidr_input = input("\033[97m  Enter CIDR block(s): \033[0m").strip()
    if not cidr_input:
        print_error("No input provided.")
        return

    cidrs = CIDR_REGEX.findall(cidr_input)
    if not cidrs:
        print_error("No valid CIDR blocks found. Use format: x.x.x.x/xx")
        return

    total_ips = 0
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            host_count = sum(1 for _ in network.hosts())
            print_info(f"{cidr} -> {host_count:,} hosts")
            total_ips += host_count
        except ValueError as e:
            print_error(f"Invalid CIDR {cidr}: {e}")

    if total_ips > 10000:
        print_warn(f"Total IPs: {total_ips:,} - this will take a while.")
        confirm = input("\033[97m  Continue? [y/N]: \033[0m").strip().lower()
        if confirm != "y":
            print_info("Cancelled.")
            return

    ips = parse_ips_from_input(cidr_input)
    if not ips:
        print_error("No valid IPs generated from CIDR blocks.")
        return

    print_success(f"Generated {len(ips):,} IPs from {len(cidrs)} CIDR block(s)")

    methods = select_methods(ip_count=len(ips))
    threads = select_threads(ip_count=len(ips))

    label = cidrs[0].replace("/", "_") if len(cidrs) == 1 else "cidr_multi"
    run_scan(ips, methods, threads, label)


def mode_file():
    print_header("File Input")
    print()
    print_info("Load IPs and/or CIDR blocks from a text file.")
    print_info("The file can contain IPs, CIDRs, or mixed content.")
    print_info("The tool uses regex to extract all valid IPs and CIDRs.")
    print()

    filepath = input("\033[97m  Enter file path: \033[0m").strip()
    if not filepath:
        print_error("No file path entered.")
        return

    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}")
        return

    ips = parse_ips_from_file(filepath)
    if not ips:
        print_error("No valid IPs or CIDR blocks found in file.")
        return

    print_success(f"Extracted {len(ips):,} IP(s) from {filepath}")

    if len(ips) <= 10:
        for ip in ips:
            print(f"\033[90m    {ip}\033[0m")
    else:
        for ip in ips[:5]:
            print(f"\033[90m    {ip}\033[0m")
        print(f"\033[90m    ... and {len(ips) - 5:,} more\033[0m")

    if len(ips) > 10000:
        print_warn(f"Total IPs: {len(ips):,} - this will take a while.")
        confirm = input("\033[97m  Continue? [y/N]: \033[0m").strip().lower()
        if confirm != "y":
            print_info("Cancelled.")
            return

    methods = select_methods(ip_count=len(ips))
    threads = select_threads(ip_count=len(ips))

    base_name = os.path.splitext(os.path.basename(filepath))[0]
    run_scan(ips, methods, threads, base_name)


def main():
    print_banner()

    while True:
        print("\033[97m  ---- Menu ----\033[0m")
        print("    1) Single IP lookup")
        print("    2) Multiple IPs (comma/space separated)")
        print("    3) CIDR block(s)")
        print("    4) Load from file (IPs, CIDRs, or mixed)")
        print("    5) Quit")
        print()

        choice = input("\033[97m  Choose an option [1-5]: \033[0m").strip()

        if choice == "1":
            mode_single_ip()
            print()

        elif choice == "2":
            mode_multiple_ips()
            print()

        elif choice == "3":
            mode_cidr()
            print()

        elif choice == "4":
            mode_file()
            print()

        elif choice in ("5", "q", "quit", "exit"):
            print()
            print_info("Goodbye!")
            print()
            break

        else:
            print_error("Invalid choice. Please enter 1-5.")
            print()


if __name__ == "__main__":
    main()
