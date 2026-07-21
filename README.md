# Port Scanner

Async TCP port scanner with banner grabbing, service detection, and CVE lookup.

> **⚠️ Legal Notice:** Port scanning without explicit permission from the target owner is illegal in many jurisdictions. This tool is intended for authorized security assessments, penetration testing, and educational purposes only. You are responsible for complying with all applicable laws.

## Features

- **Async concurrent scanning** — uses `asyncio` for efficient I/O-bound port scanning
- **Banner grabbing** — captures service banners from open ports with regex-based parsing
- **Service detection** — fallback to well-known port mapping when banner parsing fails
- **CVE lookup** — queries NVD API for known vulnerabilities with rate limiting and retry
- **Configurable** — port range, timeout, concurrency, delay, scan timeout, and output file via CLI
- **Progress bar** — real-time scan progress with `tqdm`
- **Save output** — export results to a file with `-o`
- **Overall scan timeout** — prevent hangs with `--scan-timeout`
- **Rate limiting** — respects NVD API limits (6s interval without key, 0.6s with key)
- **Verbose mode** — `--verbose` for debug-level logging to aid troubleshooting

## Requirements

- Python 3.9+
- `requests`, `tqdm` libraries

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

Or directly:

```bash
python portScanner.py <target> [options]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `target` | — | Target IP address or hostname (required) |
| `--port-start` | 20 | Starting port |
| `--port-end` | 3306 | Ending port |
| `--timeout` | 1 | Socket timeout in seconds |
| `--threads` | 50 | Number of concurrent tasks |
| `--delay` | 0 | Delay between scans in seconds |
| `-o, --output` | — | Save results to file |
| `--scan-timeout` | 0 | Total scan timeout in seconds (0 = no limit) |
| `--verbose, -v` | — | Enable debug-level logging for troubleshooting |

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

# Scan common ports only
port-scanner 192.168.1.1 --port-start 1 --port-end 1024

# Fast scan with higher concurrency and lower timeout
port-scanner 10.0.0.1 --timeout 0.5 --threads 100

# Slow scan with delay to avoid detection
port-scanner 192.168.1.1 --delay 0.1 --threads 10

# Save results to file
port-scanner scanme.nmap.org -o results.txt

# Verbose mode for troubleshooting
port-scanner 192.168.1.1 --verbose
```

## Output

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

## Development

Run tests, type checking, and linting:

```bash
pytest -v
mypy portScanner.py
ruff check portScanner.py test_portScanner.py
```

## Notes

- Banner grabbing sends `\r\n` and reads up to 1024 bytes
- CVE lookup is limited to the first 3 results per service and normalizes versions for broader matching
- Use `--delay` to rate-limit scans and avoid being blocked
- NVD API rate limits apply: 5 req/30s without key, 50 req/30s with key
- IPv6 addresses are accepted but resolved via `socket.gethostbyname()` which returns an IPv4 address; IPv6-only hosts are not supported
