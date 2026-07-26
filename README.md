# Port Scanner

Async TCP port scanner with banner grabbing, service detection, and CVE lookup.

> **⚠️ Legal Notice:** Port scanning without explicit permission from the target owner is illegal in many jurisdictions. This tool is intended for authorized security assessments, penetration testing, and educational purposes only. You are responsible for complying with all applicable laws.

## Features

- **Async concurrent scanning** — uses `asyncio` for efficient I/O-bound port scanning
- **Banner grabbing** — captures service banners from open ports with regex-based parsing
- **Service detection** — fallback to well-known port mapping when banner parsing fails
- **CVE lookup** — CPE-based matching for known services with NVD API rate limiting and retry
- **Flexible port specification** — ranges (`1-1000`), comma lists (`22,80,443`), named sets (`common`, `all`)
- **CIDR & multi-target** — scan entire subnets or load targets from a file
- **Timing profiles** — preset profiles 0–5 (paranoid to insane)
- **Multiple output formats** — text, JSON, or CSV
- **Progress bar** — real-time scan progress with `tqdm`
- **Overall scan timeout** — prevent hangs with `--scan-timeout`
- **Scanner rate limiting** — control connections per second with `--max-rate` (token bucket)
- **IPv6 support** — force IPv6 resolution with `--ipv6`
- **Verbose mode** — `--verbose` for debug-level logging to aid troubleshooting

## Requirements

- Python 3.9+
- `aiohttp`, `tqdm` libraries

Install:

```bash
pip install port-scanner
```

Or for development:

```bash
git clone <repo>
cd portScanner
pip install -e ".[dev]"
```

## Usage

```bash
port-scanner <target> [options]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `target` | — | Target IP address, hostname, or CIDR (e.g. `192.168.1.0/24`) |
| `-iL, --input-list` | — | File containing target hosts/networks (one per line, `#` comments) |
| `-p, --ports` | — | Port specification: `22,80,443`, `1-1000`, `common`, or `all` |
| `--port-start` | 20 | Starting port (when `-p` is not used) |
| `--port-end` | 3306 | Ending port (when `-p` is not used) |
| `--timeout` | 1 | Socket timeout in seconds |
| `--threads` | 50 | Number of concurrent tasks |
| `--delay` | 0 | Delay between scans in seconds |
| `-T, --timing` | — | Timing profile 0–5 (paranoid→insane, overrides timeout/threads/delay) |
| `-f, --format` | text | Output format: `text`, `json`, or `csv` |
| `--max-rate` | 0 | Max connections per second (0 = unlimited, token bucket) |
| `-o, --output` | — | Save results to file |
| `--scan-timeout` | 0 | Total scan timeout in seconds (0 = no limit) |
| `-6, --ipv6` | — | Force IPv6 resolution |
| `-v, --verbose` | — | Enable debug-level logging for troubleshooting |

### Timing Profiles

| Profile | Name | Timeout | Threads | Delay |
|---|---|---|---|---|
| 0 | Paranoid | 5.0s | 5 | 5.0s |
| 1 | Sneaky | 2.0s | 10 | 1.0s |
| 2 | Polite | 1.0s | 25 | 0.1s |
| 3 | Normal | 1.0s | 50 | 0.0s |
| 4 | Aggressive | 0.5s | 100 | 0.0s |
| 5 | Insane | 0.3s | 200 | 0.0s |

### CVE Lookup

Set the `NVD_API_KEY` environment variable for higher rate limits (50 req/30s instead of 5 req/30s):

```bash
export NVD_API_KEY=your-key-here
port-scanner scanme.nmap.org
```

### Examples

```bash
# Scan default range (20-3306)
port-scanner 192.168.1.1

# Scan specific ports
port-scanner scanme.nmap.org -p 22,80,443,8080

# Scan common ports (well-known list)
port-scanner 10.0.0.1 -p common

# Scan all 65535 ports
port-scanner 192.168.1.1 -p all

# Scan a subnet
port-scanner 192.168.1.0/28

# Scan targets from a file
port-scanner -iL targets.txt

# Fast scan with aggressive timing
port-scanner 10.0.0.1 -T 4

# Slow scan to avoid detection
port-scanner 192.168.1.1 -T 0

# Export results as JSON
port-scanner scanme.nmap.org -f json -o results.json

# Export results as CSV
port-scanner scanme.nmap.org -f csv -o results.csv

# Limit to 10 connections per second
port-scanner 192.168.1.1 --max-rate 10

# Scan with overall timeout
port-scanner scanme.nmap.org --scan-timeout 60

# Verbose mode for troubleshooting
port-scanner 192.168.1.1 --verbose
```

## Output

### Text format

```
============================================================
  Port Scanner — Target: 45.33.32.156
  Range: 20-3306 (3287 ports)
  Workers: 50 | Timeout: 1s | Delay: 0s
  Started: 2026-07-20 12:49:09
============================================================
   PORT  SERVICE        VERSION
------------------------------------------------------------
  OPEN    22  OpenSSH        6.6.1p1
         Found 2 CVE(s):
           - CVE-2014-2532: sshd in OpenSSH before 6.6 ...
           - CVE-2014-2653: The verify_host_key function ...
  OPEN    80  HTTP            unknown
         No CVEs found
============================================================
  Scan complete: 2/3287 ports open
  Duration: 0:00:14.687
  Finished: 2026-07-20 12:55:08
============================================================
```

### JSON format

```json
{
  "targets": ["45.33.32.156"],
  "port_start": 20,
  "port_end": 3306,
  "total_ports": 3287,
  "duration_seconds": 14.69,
  "open_ports_count": 2,
  "results": [
    {"target": "45.33.32.156", "port": 22, "service": "OpenSSH", "version": "6.6.1p1", "cve": "..."},
    {"target": "45.33.32.156", "port": 80, "service": "HTTP", "version": "unknown", "cve": "..."}
  ]
}
```

### CSV format

```csv
target,port,service,version,cve
45.33.32.156,22,OpenSSH,6.6.1p1,...
45.33.32.156,80,HTTP,unknown,...
```

## Development

```bash
pytest -v
mypy portScanner/
ruff check portScanner/ test_portScanner.py
```

## Notes

- Banner grabbing sends protocol-appropriate probes: `\r\n` (generic), `GET / HTTP/1.0` (HTTP), `EHLO` (SMTP), `PING` (Redis), `CAPABILITY` (IMAP), `CAPA` (POP3)
- Banner response is read up to 4096 bytes; service detection uses regex patterns for SSH, FTP, HTTP, SMTP, IMAP, POP3, and generic name/version
- CVE lookup uses CPE exact matching for known services (OpenSSH, Apache, nginx, Postfix, Dovecot, Exim, etc.) with fallback to `cpeMatchString` then keyword search
- CVE results are limited to the first 3 per service; versions are normalized to major.minor for broader matching
- Use `--delay`, `--max-rate`, or timing profiles to control scan aggressiveness
- NVD API rate limits apply: 5 req/30s without key, 50 req/30s with key
- IPv6 is supported natively via `getaddrinfo`; use `--ipv6` to force IPv6 resolution
- CIDR notation expands to all host addresses in the network
