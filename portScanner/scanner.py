from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import time
from datetime import datetime
from typing import Any

import aiohttp
from tqdm import tqdm

logger: logging.Logger = logging.getLogger("portScanner")

DEFAULT_PORT_START: int = 20
DEFAULT_PORT_END: int = 3306
DEFAULT_TIMEOUT: float = 1.0
DEFAULT_THREADS: int = 50
DEFAULT_DELAY: float = 0.0
DEFAULT_SCAN_TIMEOUT: float = 0.0

SERVICE_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "SunRPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
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


class PortScanner:
    service_ports: dict[int, str]
    open_ports: list[int]
    results: list[dict[str, str | int]]
    api_key: str | None
    _rate_lock: asyncio.Lock
    _ports_lock: asyncio.Lock
    _last_request_time: float
    _rate_interval: float

    def __init__(self, service_ports: dict[int, str] | None = None, api_key: str | None = None) -> None:
        self.service_ports = service_ports or SERVICE_PORTS
        self.open_ports = []
        self.results = []
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._rate_lock = asyncio.Lock()
        self._ports_lock = asyncio.Lock()
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

        logger.debug("Looking up CVEs for %s %s", service, version)
        async with aiohttp.ClientSession() as session:
            for attempt in range(3):
                async with self._rate_lock:
                    elapsed = time.monotonic() - self._last_request_time
                    if elapsed < self._rate_interval:
                        logger.debug("Rate limit: sleeping %.1fs", self._rate_interval - elapsed)
                        await asyncio.sleep(self._rate_interval - elapsed)
                    self._last_request_time = time.monotonic()

                try:
                    async with session.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as response:
                        if response.status == 429:
                            try:
                                retry_after = int(response.headers.get("Retry-After", 5))
                            except (ValueError, TypeError):
                                retry_after = 5
                            await asyncio.sleep(retry_after)
                            continue
                        response.raise_for_status()
                        data = await response.json()
                except aiohttp.ClientResponseError as e:
                    status = e.status
                    if 400 <= status < 500 and status != 429:
                        return f"         [!] CVE lookup failed (client error {status}): {e}\n"
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return f"         [!] CVE lookup failed: {e}\n"
                except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return f"         [!] CVE lookup failed: {e}\n"
                except (aiohttp.ClientError, ValueError) as e:
                    return f"         [!] CVE lookup failed: {e}\n"
                else:
                    break
            else:
                return "         [!] CVE lookup failed after 3 attempts\n"

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

        logger.debug("Connecting to %s:%d", ip, port)
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError):
            logger.debug("Port %d: connection refused or timed out", port)
            return

        logger.debug("Port %d: connected", port)

        async with self._ports_lock:
            self.open_ports.append(port)

        service = "unknown"
        version = "unknown"
        cve_output: str = ""

        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            banner: bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)

            logger.debug("Port %d: raw banner %r", port, banner)
            svc, ver = self._parse_banner(banner)
            if svc is not None:
                service = svc
                version = ver if ver is not None else "unknown"
            else:
                service = self.service_ports.get(port, "unknown")

            if service != "unknown" and version is not None:
                cve_output = await self._get_cve_text(service, version)

            logger.info("  OPEN  %5d  %-14s %-8s", port, service, version)
            if cve_output:
                logger.info(cve_output.rstrip("\n"))
        except (OSError, asyncio.TimeoutError):
            logger.debug("Port %d: banner grab timed out", port)
        finally:
            async with self._ports_lock:
                self.results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "cve": cve_output,
                })
            writer.close()
            await writer.wait_closed()

    async def scan(
        self, target_ip: str, port_start: int = DEFAULT_PORT_START,
        port_end: int = DEFAULT_PORT_END, timeout: float = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS, delay: float = DEFAULT_DELAY,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        self.open_ports = []
        self.results = []

        if not 1 <= port_start <= 65535:
            logger.error("port_start must be between 1 and 65535, got %d", port_start)
            return
        if not 1 <= port_end <= 65535:
            logger.error("port_end must be between 1 and 65535, got %d", port_end)
            return
        if port_start > port_end:
            logger.error("port_start (%d) must not exceed port_end (%d)", port_start, port_end)
            return
        if timeout <= 0:
            logger.error("timeout must be positive, got %s", timeout)
            return
        if threads < 1:
            logger.error("threads must be at least 1, got %d", threads)
            return
        if delay < 0:
            logger.error("delay must be non-negative, got %s", delay)
            return
        if scan_timeout < 0:
            logger.error("scan_timeout must be non-negative, got %s", scan_timeout)
            return

        try:
            ip: str = socket.gethostbyname(target_ip)
            logger.debug("Resolved %s to %s", target_ip, ip)

            total_ports: int = port_end - port_start + 1
            start_time: datetime = datetime.now()
            logger.info("=" * 60)
            logger.info("  Port Scanner — Target: %s", ip)
            logger.info("  Range: %d-%d (%d ports)", port_start, port_end, total_ports)
            logger.info("  Workers: %d | Timeout: %ss | Delay: %ss", threads, timeout, delay)
            logger.info("  Started: %s", start_time)
            logger.info("=" * 60)
            logger.info("%7s  %-14s %-8s", "PORT", "SERVICE", "VERSION")
            logger.info("-" * 60)

            sem: asyncio.Semaphore = asyncio.Semaphore(threads)

            async def _scan(port: int) -> None:
                async with sem:
                    await self._scan_port(ip, port, timeout, delay)

            tasks: list[asyncio.Task[None]] = [asyncio.create_task(_scan(port))
                                                for port in range(port_start, port_end + 1)]

            async def _run() -> None:
                try:
                    for coro in tqdm(asyncio.as_completed(tasks), total=total_ports,
                                     desc="Scanning", unit="port", ncols=80):
                        await coro
                except asyncio.CancelledError:
                    for t in tasks:
                        t.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    raise

            logger.debug("Created %d scan tasks with %d workers", total_ports, threads)
            if scan_timeout > 0:
                logger.debug("Scan timeout enabled: %ss", scan_timeout)
                await asyncio.wait_for(_run(), timeout=scan_timeout)
            else:
                await _run()

            end_time: datetime = datetime.now()
            logger.info("=" * 60)
            logger.info("  Scan complete: %d/%d ports open", len(self.open_ports), total_ports)
            logger.info("  Duration: %s", end_time - start_time)
            logger.info("  Finished: %s", end_time)
            logger.info("=" * 60)

        except socket.gaierror:
            try:
                socket.getaddrinfo(target_ip, None, socket.AF_INET6)
                logger.error("Hostname resolves to IPv6 only, which is not supported")
            except socket.gaierror:
                logger.error("Hostname cannot be resolved")

        except socket.error:
            logger.error("Could not connect to the server")

        except asyncio.TimeoutError:
            logger.error("Scan timed out")

        except asyncio.CancelledError:
            end_time = datetime.now()
            logger.warning("=" * 60)
            logger.warning("  Scan cancelled by user")
            logger.warning("  Partial results: %d/%d ports open", len(self.open_ports), total_ports)
            logger.warning("  Duration: %s", end_time - start_time)
            logger.warning("=" * 60)
            raise

        except Exception:
            logger.exception("Unexpected error during scan")
