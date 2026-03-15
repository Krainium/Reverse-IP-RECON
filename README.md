# ReverseDNS — Reverse DNS IP Lookup Tool

A Python CLI tool that resolves IP addresses back to domain names in bulk. Supports single IPs, multiple IPs, CIDR blocks (`/0` to `/32`), and file input with automatic regex extraction. Uses PTR records, RapidDNS, and HackerTarget APIs with multi-threaded scanning and real-time result saving.

Created by **Krainium**.

---

## Aim

To provide a fast, reliable way to discover what domains and hostnames are behind IP addresses at scale. Whether you have a single IP you want to identify, a `/24` subnet to map, or millions of IPs from a full CIDR range, this tool handles it from one script. It's built for network administrators doing infrastructure audits, security researchers mapping attack surfaces, and anyone who needs to go from IP addresses to domain names quickly. Results save in real-time as scanning proceeds — no waiting until the end, no lost progress if you stop early.

---

## Features

- **Single IP, multiple IPs, CIDR blocks, or file input** — handles any format
- **CIDR support from /0 to /32** — auto-expands any subnet into individual host IPs
- **Flexible input parsing** — accepts `"x.x.x.x"`, `'x.x.x.x'`, `[x.x.x.x, x.x.x.x]`, comma-separated, space-separated, or mixed
- **Regex extraction from files** — drop in any text file and the tool picks out all IPs and CIDRs automatically
- **3 lookup methods** — PTR records (instant), RapidDNS API, HackerTarget API
- **Smart defaults for large scans** — auto-recommends PTR only for 50,000+ IPs, warns about API request counts
- **ETA estimates** — shows estimated scan time before starting
- **Multi-threaded** — up to 500 concurrent threads, auto-scales default based on scan size
- **Real-time saving** — results append to files as each IP is resolved, not at the end
- **tqdm progress bar** — live progress with speed, ETA, and completion percentage
- **Domains displayed live** — hostnames print as they're found during scanning
- **Styled output** — pyfiglet ASCII banner with color-coded results
- **Works on Windows, macOS, and Linux**

---

## Preview

```
    ____                                ____  _   _______
   / __ \___ _   _____  _____________  / __ \/ | / / ___/
  / /_/ / _ \ | / / _ \/ ___/ ___/ _ \/ / / /  |/ /\__ \ 
 / _, _/  __/ |/ /  __/ /  (__  )  __/ /_/ / /|  /___/ / 
/_/ |_|\___/|___/\___/_/  /____/\___/_____/_/ |_//____/  

  Reverse DNS IP Lookup Tool
  Resolve IPs, CIDR blocks, and IP lists
  back to domain names in bulk.

  ─────────────────────────────────────────────

  ---- Menu ----
    1) Single IP lookup
    2) Multiple IPs (comma/space separated)
    3) CIDR block(s)
    4) Load from file (IPs, CIDRs, or mixed)
    5) Quit
```

---

## Requirements

- **Python 3.7+** — [Download here](https://www.python.org/downloads/)
- Two pip packages:

```bash
pip install pyfiglet tqdm
```

No other dependencies. All DNS and HTTP operations use Python built-in modules (`socket`, `http.client`).

---

## Quick Start

```bash
pip install pyfiglet tqdm
python reverse.py
```

---

## Usage

### 1) Single IP Lookup

Resolve one IP address to its associated domain names:

```
  [Single IP Lookup]

  Enter IP address: 8.8.8.8
  [*] Target: 8.8.8.8

  [Lookup Methods]
    1) PTR records only (fastest, ~1000+ IPs/sec)
    2) PTR + RapidDNS (slower, HTTP request per IP)
    3) PTR + HackerTarget (slower, HTTP request per IP)
    4) PTR + RapidDNS + HackerTarget (slowest, 2 HTTP requests per IP)
    5) RapidDNS + HackerTarget (skip PTR)

  Choose methods [1-5, default 4]: 4

  ─────────────────────────────────────────────
  [Scan Configuration]
  [*] IPs to scan:   1
  [*] Methods:       ptr, rapiddns, hackertarget
  [*] Threads:       1
  [*] Est. time:     ~3s
  [*] Output folder: reverse-dns-results/8.8.8.8_20260315_163000
  ─────────────────────────────────────────────

  [+] dns.google
  [+] google-public-dns-a.google.com
    Scanning: 100%|████████████████████████████████████████| 1/1 [00:02<00:00]

  ─────────────────────────────────────────────
  [Scan Results]
  [+] IPs scanned:      1
  [+] IPs with domains: 1
  [*] Unique domains:   2
  [*] Hit rate:         100.0%
  ─────────────────────────────────────────────
```

### 2) Multiple IPs

Enter IPs in any format — commas, spaces, brackets, quoted, or mixed with CIDRs:

```
  Enter IPs/CIDRs: 8.8.8.8, 1.1.1.1, 9.9.9.9
  [+] Parsed 3 IP(s)
```

All of these formats work:

```
8.8.8.8, 1.1.1.1, 9.9.9.9
8.8.8.8 1.1.1.1 9.9.9.9
[8.8.8.8, 1.1.1.1, 9.9.9.9]
["8.8.8.8", "1.1.1.1", "9.9.9.9"]
['8.8.8.8', '1.1.1.1']
"8.8.8.8", "1.1.1.1", 192.168.1.0/28
```

### 3) CIDR Block(s)

Enter one or more CIDR blocks to expand and scan:

```
  Enter CIDR block(s): 104.16.0.0/24, 172.67.0.0/28
  [*] 104.16.0.0/24 -> 254 hosts
  [*] 172.67.0.0/28 -> 14 hosts
  [+] Generated 268 IPs from 2 CIDR block(s)
```

**Supported CIDR ranges:**

| CIDR | Hosts | Example |
|------|-------|---------|
| `/32` | 1 | Single IP |
| `/28` | 14 | Small subnet |
| `/24` | 254 | Standard subnet |
| `/20` | 4,094 | Large subnet |
| `/16` | 65,534 | Class B network |
| `/12` | 1,048,574 | Large block |
| `/8` | 16,777,214 | Class A network |
| `/0` | 4,294,967,294 | Entire IPv4 space |

For very large CIDR blocks (>10,000 IPs), the tool confirms before proceeding.

### 4) Load from File

Point to any text file containing IPs, CIDRs, or both. The tool uses regex to extract all valid entries automatically — the file can contain other text, comments, or formatting:

```
  Enter file path: cloudflare-ranges.txt
  [+] Extracted 1,786,852 IP(s) from cloudflare-ranges.txt
    103.21.244.1
    103.21.244.2
    103.21.244.3
    103.21.244.4
    103.21.244.5
    ... and 1,786,847 more
```

**Example file contents** (all of these are extracted correctly):

```
# Cloudflare IP ranges
103.21.244.0/22
104.16.0.0/13
"172.64.0.0/13"
'131.0.72.0/22'

Some random text here, ignored.

Individual IPs:
8.8.8.8
1.1.1.1
```

### 5) Quit

Exit the program. All results from completed scans are already saved.

---

## Lookup Methods Explained

Before each scan, you choose which methods to use:

| Option | Methods | Speed | Best For |
|--------|---------|-------|----------|
| 1 | PTR only | ~1,000+ IPs/sec | Large scans (10,000+ IPs) |
| 2 | PTR + RapidDNS | ~1 IP/sec | Medium scans, more coverage |
| 3 | PTR + HackerTarget | ~1 IP/sec | Medium scans, alternative API |
| 4 | PTR + RapidDNS + HackerTarget | ~0.5 IP/sec | Small scans, maximum coverage |
| 5 | RapidDNS + HackerTarget | ~0.5 IP/sec | When PTR is unreliable |

**PTR records** — instant DNS reverse lookup built into the internet. Every IP can have a PTR record pointing to a hostname. Fast but limited to one hostname per IP.

**RapidDNS** (rapiddns.io) — free web service that indexes DNS records. Returns all domains that have ever pointed to an IP. Finds virtual hosts and shared hosting neighbors.

**HackerTarget** (hackertarget.com) — free reverse IP API. Similar to RapidDNS but with a different database, often finding domains the other misses.

### Smart Defaults for Large Scans

For scans over 50,000 IPs, the default automatically switches to PTR only. If you choose an API method on a large scan, the tool warns you:

```
  [!] You have 1,786,852 IPs. Methods 2-5 make HTTP requests per IP.
  [!] Method 2 = 1,786,852 HTTP requests (~29,781 minutes minimum).
  [!] For large scans, PTR only (option 1) is strongly recommended.
```

---

## Thread Scaling

Default thread count adjusts based on scan size:

| IP Count | Default Threads | Max Allowed |
|----------|----------------|-------------|
| < 10,000 | 20 | 500 |
| 10,000 - 100,000 | 50 | 500 |
| > 100,000 | 100 | 500 |

You can override the default at the prompt. For PTR-only scans, higher thread counts (100-200) work well since PTR lookups are lightweight DNS queries.

---

## Output

### Real-Time Saving

Results save as each IP is resolved — you never lose progress. If you stop a scan with Ctrl+C, everything found so far is already on disk.

### Output Files

Each scan creates a timestamped folder in `reverse-dns-results/`:

```
reverse-dns-results/
  cf_20260315_163000/
    domains.txt           # All domains found (one per line)
    domains_sorted.txt    # Deduplicated and sorted
    ips_with_domains.txt  # IPs that had results
    ips_no_results.txt    # IPs with no reverse DNS
    scan_info.txt         # Scan metadata and stats
```

### domains.txt

```
cloudflare.com
www.cloudflare.com
blog.cloudflare.com
api.cloudflare.com
dash.cloudflare.com
```

### scan_info.txt

```
Scan started: 2026-03-15T16:30:00.000000
Total IPs: 254
Methods: ptr
Threads: 100
Scan completed: 2026-03-15T16:30:05.000000
IPs with domains: 187
IPs no results: 67
Total domains found: 312
Unique domains: 245
Elapsed: 0m 5s
```

---

## Scan Results Summary

After every scan, a stats summary is displayed:

```
  ─────────────────────────────────────────────
  [Scan Results]
  [+] IPs scanned:      254
  [+] IPs with domains: 187
  [-] IPs no results:   67
  [*] Total domains:    312
  [*] Unique domains:   245
  [*] Time elapsed:     0m 5s
  [*] Speed:            50.8 IPs/sec
  [*] Hit rate:         73.6%
  ─────────────────────────────────────────────

  [+] All results saved to: reverse-dns-results/104.16.0.0_24_20260315_163000/
  Files:
    domains.txt                    4.2 KB
    domains_sorted.txt             3.8 KB
    ips_no_results.txt             871 B
    ips_with_domains.txt           2.4 KB
    scan_info.txt                  312 B
```

---

## Input Format Reference

| Format | Example | Works? |
|--------|---------|--------|
| Plain IP | `8.8.8.8` | Yes |
| Double-quoted IP | `"8.8.8.8"` | Yes |
| Single-quoted IP | `'8.8.8.8'` | Yes |
| Comma-separated | `8.8.8.8, 1.1.1.1` | Yes |
| Space-separated | `8.8.8.8 1.1.1.1` | Yes |
| Bracket array | `[8.8.8.8, 1.1.1.1]` | Yes |
| Quoted bracket array | `["8.8.8.8", "1.1.1.1"]` | Yes |
| CIDR block | `192.168.1.0/24` | Yes |
| Quoted CIDR | `"10.0.0.0/16"` | Yes |
| Mixed IPs and CIDRs | `8.8.8.8, 10.0.0.0/24` | Yes |
| File with any format | Text file path | Yes |

---

## Performance Guide

### PTR Only (Recommended for Large Scans)

| IPs | Threads | Estimated Time |
|-----|---------|---------------|
| 254 (/24) | 20 | ~5 seconds |
| 4,094 (/20) | 50 | ~1 minute |
| 65,534 (/16) | 100 | ~10 minutes |
| 1,000,000+ | 100-200 | ~20-60 minutes |

### With API Methods

| IPs | Method | Threads | Estimated Time |
|-----|--------|---------|---------------|
| 100 | PTR + RapidDNS + HackerTarget | 20 | ~30 seconds |
| 1,000 | PTR + RapidDNS | 20 | ~8 minutes |
| 10,000+ | Any API method | Any | Not recommended |

---

## Troubleshooting

### "Missing required package"

```bash
pip install pyfiglet tqdm
```

If you have both Python 2 and 3:
```bash
pip3 install pyfiglet tqdm
```

### Scan appears stuck at 0%

- If using API methods (RapidDNS/HackerTarget) on a large scan, each IP makes an HTTP request that takes 1-5 seconds. Switch to PTR only (option 1).
- Check your internet connection.
- Try increasing thread count.

### Very low hit rate

- Many IP ranges (especially cloud providers) don't have PTR records configured.
- Try adding RapidDNS or HackerTarget for more coverage (only practical for smaller scans).
- Some IP ranges are simply unallocated and will have no results.

### "Total IPs: X - this will take a while"

For very large CIDR blocks, the tool warns you before proceeding. Consider:
- Scanning a smaller subnet first (e.g. `/24` instead of `/16`).
- Using PTR only with high thread count.

### Permission errors on Windows

Run the command prompt as Administrator or use a directory you have write access to.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| [pyfiglet](https://pypi.org/project/pyfiglet/) | ASCII art banner |
| [tqdm](https://pypi.org/project/tqdm/) | Progress bar with speed and ETA |

All DNS and HTTP networking uses Python built-in modules:
- `socket` — PTR record lookups
- `http.client` — HTTPS requests to RapidDNS and HackerTarget APIs
- `ipaddress` — CIDR block expansion
- `threading` — concurrent scanning
