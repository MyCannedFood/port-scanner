from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import socket
import sys
import time
from datetime import datetime
from typing import Any

import requests
from tqdm import tqdm

DEFAULT_PORT_START: int = 20
DEFAULT_PORT_END: int = 3306
DEFAULT_TIMEOUT: float = 1.0
DEFAULT_THREADS: int = 50
DEFAULT_DELAY: float = 0.0

SERVICE_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


BANNER_PATTERNS: list[re.Pattern[bytes]] = [
    re.compile(rb"SSH-[\d.]+-(\w[\w.-]*?)[_ ](\d[\w.]*)"),
    re.compile(rb"220[- ](\w[\w.-]*) ([\d.]+)"),
    re.compile(rb"Server:\s*(\w[\w.-]+)/([\d.]+)", re.IGNORECASE),
    re.compile(rb"(\w[\w.-]+)/([\d.]+)"),
    re.compile(rb"(\w[\w.-]+)\s+v?([\d.]+)"),
]


class Tee:
    file: Any
    stdout: Any

    def __init__(self, filepath: str) -> None:
        try:
            self.file = open(filepath, "w")
        except OSError as e:
            print(f"Error: cannot open output file '{filepath}': {e}")
            sys.exit(1)
        self.stdout = sys.stdout

    def write(self, text: str) -> None:
        self.stdout.write(text)
        self.file.write(text)

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def close(self) -> None:
        self.file.close()


class PortScanner:
    service_ports: dict[int, str]
    open_ports: list[int]
    api_key: str | None
    _rate_lock: asyncio.Lock
    _last_request_time: float
    _rate_interval: float

    def __init__(self, service_ports: dict[int, str] | None = None, api_key: str | None = None) -> None:
        self.service_ports = service_ports or SERVICE_PORTS
        self.open_ports = []
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._rate_lock = asyncio.Lock()
        self._last_request_time = 0.0
        self._rate_interval = 6.0 if not self.api_key else 0.6

    @staticmethod
    def _normalize_version(version: str) -> str:
        ver = re.sub(r"p\d+$", "", version)
        parts = ver.split(".")
        return ".".join(parts[:2])

    async def _get_cve_text(self, service: str, version: str) -> str:
        version = self._normalize_version(version)
        params: dict[str, str | int] = {"keywordSearch": f"{service} {version}"}
        if self.api_key:
            params["apiKey"] = self.api_key

        for attempt in range(3):
            async with self._rate_lock:
                elapsed = time.monotonic() - self._last_request_time
                if elapsed < self._rate_interval:
                    await asyncio.sleep(self._rate_interval - elapsed)
                self._last_request_time = time.monotonic()

            try:
                response = await asyncio.to_thread(
                    requests.get,
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                    timeout=10
                )
                if response.status_code == 429:
                    try:
                        retry_after = int(response.headers.get("Retry-After", 5))
                    except (ValueError, TypeError):
                        retry_after = 5
                    await asyncio.sleep(retry_after)
                    continue
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if 400 <= status < 500 and status != 429:
                    return f"         [!] CVE lookup failed (client error {status}): {e}\n"
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return f"         [!] CVE lookup failed: {e}\n"
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return f"         [!] CVE lookup failed: {e}\n"
            except requests.exceptions.RequestException as e:
                return f"         [!] CVE lookup failed: {e}\n"
            else:
                break
        else:
            return "         [!] CVE lookup failed after 3 attempts\n"

        try:
            data: Any = response.json()
        except ValueError as e:
            return f"         [!] Failed to parse CVE response: {e}\n"

        vulns: list[Any] = data.get("vulnerabilities", [])
        if not vulns:
            return "         No CVEs found\n"

        lines: list[str] = [f"         Found {len(vulns)} CVE(s):\n"]
        for item in vulns[:3]:
            cve: Any = item.get("cve", {})
            cve_id: str = cve.get("id", "N/A")
            desc: str = "N/A"
            if "descriptions" in cve:
                for d in cve["descriptions"]:
                    if d.get("lang") == "en":
                        desc = d.get("value", "N/A")
                        break
            lines.append(f"           - {cve_id}: {desc[:120]}\n")
        return "".join(lines)

    @staticmethod
    def _parse_banner(banner: bytes) -> tuple[str | None, str | None]:
        for pattern in BANNER_PATTERNS:
            match = pattern.search(banner)
            if match:
                svc = match.group(1).decode("utf-8", errors="replace")
                ver = match.group(2).decode("utf-8", errors="replace")
                return svc, ver
        return None, None

    async def _scan_port(self, ip: str, port: int, timeout: float, delay: float) -> None:
        await asyncio.sleep(delay)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError):
            return

        self.open_ports.append(port)

        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            banner: bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            writer.close()
            await writer.wait_closed()
            return

        service, version = self._parse_banner(banner)
        if service is None:
            service = self.service_ports.get(port, "unknown")
            version = "unknown"

        cve_output: str = ""
        if service != "unknown" and version is not None:
            cve_output = await self._get_cve_text(service, version)

        print(f"  OPEN  {port:>5}  {service:<14} {version:<8}")
        if cve_output:
            print(cve_output, end="")

        writer.close()
        await writer.wait_closed()

    async def scan(
        self, target_ip: str, port_start: int = DEFAULT_PORT_START,
        port_end: int = DEFAULT_PORT_END, timeout: float = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS, delay: float = DEFAULT_DELAY,
    ) -> None:
        self.open_ports = []

        if not 1 <= port_start <= 65535:
            print(f"Error: port_start must be between 1 and 65535, got {port_start}")
            return
        if not 1 <= port_end <= 65535:
            print(f"Error: port_end must be between 1 and 65535, got {port_end}")
            return
        if port_start > port_end:
            print(f"Error: port_start ({port_start}) must not exceed port_end ({port_end})")
            return
        if timeout <= 0:
            print(f"Error: timeout must be positive, got {timeout}")
            return
        if threads < 1:
            print(f"Error: threads must be at least 1, got {threads}")
            return
        if delay < 0:
            print(f"Error: delay must be non-negative, got {delay}")
            return

        try:
            ip: str = socket.gethostbyname(target_ip)

            total_ports: int = port_end - port_start + 1
            start_time: datetime = datetime.now()
            print("=" * 60)
            print(f"  Port Scanner — Target: {ip}")
            print(f"  Range: {port_start}-{port_end} ({total_ports} ports)")
            print(f"  Workers: {threads} | Timeout: {timeout}s | Delay: {delay}s")
            print(f"  Started: {start_time}")
            print("=" * 60)
            print(f"{'PORT':>7}  {'SERVICE':<14} {'VERSION':<8}")
            print("-" * 60)

            sem: asyncio.Semaphore = asyncio.Semaphore(threads)

            async def _scan(port: int) -> None:
                async with sem:
                    await self._scan_port(ip, port, timeout, delay)

            tasks: list[asyncio.Task[None]] = [asyncio.create_task(_scan(port))
                                                for port in range(port_start, port_end + 1)]
            for task in tqdm(asyncio.as_completed(tasks), total=total_ports,
                             desc="Scanning", unit="port", ncols=80):
                await task

            end_time: datetime = datetime.now()
            print("=" * 60)
            print(f"  Scan complete: {len(self.open_ports)}/{total_ports} ports open")
            print(f"  Duration: {end_time - start_time}")
            print(f"  Finished: {end_time}")
            print("=" * 60)

        except socket.gaierror:
            print("Hostname cannot be resolved")

        except socket.error:
            print("Could not connect to the server")

        except asyncio.TimeoutError:
            print("Scan timed out")

        except Exception as e:
            print(f"Unexpected error during scan: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Port Scanner with banner grabbing and CVE lookup")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORT_START,
                        help=f"Start port (default: {DEFAULT_PORT_START})")
    parser.add_argument("--port-end", type=int, default=DEFAULT_PORT_END,
                        help=f"End port (default: {DEFAULT_PORT_END})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of concurrent tasks (default: {DEFAULT_THREADS})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between scans in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("-o", "--output", help="Save results to file")
    args: argparse.Namespace = parser.parse_args()

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        try:
            socket.gethostbyname(args.target)
        except socket.gaierror:
            print("Invalid IP address or hostname")
            return

    tee: Tee | None = Tee(args.output) if args.output else None
    if tee:
        sys.stdout = tee

    scanner: PortScanner = PortScanner()

    try:
        asyncio.run(scanner.scan(args.target, args.port_start, args.port_end,
                                 args.timeout, args.threads, args.delay))
    except KeyboardInterrupt:
        print("\nScan cancelled by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        if tee:
            sys.stdout = tee.stdout
            tee.close()
            print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
