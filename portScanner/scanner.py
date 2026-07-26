from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime
from typing import Any

import aiohttp
from tqdm import tqdm

from portScanner.utils import (
    BANNER_PATTERNS,
    CPE_MAP,
    DEFAULT_DELAY,
    DEFAULT_MAX_RATE,
    DEFAULT_PORT_END,
    DEFAULT_PORT_START,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    GREETING_PORTS,
    SERVICE_PORTS,
    TLS_PORTS,
    resolve_target,
)

logger: logging.Logger = logging.getLogger("portScanner")


class RateLimiter:
    def __init__(self, max_rate: float) -> None:
        self._max_rate = max_rate
        self._tokens = max_rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._max_rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max_rate, self._tokens + elapsed * self._max_rate)
            self._last_refill = now
            if self._tokens >= 1:
                self._tokens -= 1
                return
            wait = (1 - self._tokens) / self._max_rate
            self._tokens = 0.0
            self._last_refill = now + wait
        await asyncio.sleep(wait)

    @property
    def max_rate(self) -> float:
        return self._max_rate


class PortScanner:
    service_ports: dict[int, str]
    open_ports: list[int]
    results: list[dict[str, str | int]]
    api_key: str | None
    _rate_lock: asyncio.Lock
    _ports_lock: asyncio.Lock
    _last_request_time: float
    _rate_interval: float
    _rate_limiter: RateLimiter

    def __init__(self, service_ports: dict[int, str] | None = None, api_key: str | None = None,
                 max_rate: float = DEFAULT_MAX_RATE) -> None:
        self.service_ports = service_ports or SERVICE_PORTS
        self.open_ports = []
        self.results = []
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._rate_lock = asyncio.Lock()
        self._ports_lock = asyncio.Lock()
        self._last_request_time = 0.0
        self._rate_interval = 6.0 if not self.api_key else 0.6
        self._rate_limiter = RateLimiter(max_rate)

    @staticmethod
    def _normalize_version(version: str) -> str:
        ver = re.sub(r"p\d+$", "", version)
        parts = ver.split(".")
        return ".".join(parts[:2])

    async def _cve_request(self, params: dict[str, str | int]) -> list[Any] | None:
        for attempt in range(3):
            async with self._rate_lock:
                elapsed = time.monotonic() - self._last_request_time
                if elapsed < self._rate_interval:
                    logger.debug("Rate limit: sleeping %.1fs", self._rate_interval - elapsed)
                    await asyncio.sleep(self._rate_interval - elapsed)
                self._last_request_time = time.monotonic()
            try:
                async with aiohttp.ClientSession() as session:
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
                    return None
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return None
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError):
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return None
            except (aiohttp.ClientError, ValueError):
                return None
            else:
                break
        else:
            return None
        return data.get("vulnerabilities", [])

    async def _get_cve_text(self, service: str, version: str) -> str:
        version = self._normalize_version(version)
        cpe_pair = CPE_MAP.get(service)

        if cpe_pair:
            vendor, product = cpe_pair
            cpe_full = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            params: dict[str, str | int] = {"cpeName": cpe_full}
            if self.api_key:
                params["apiKey"] = self.api_key
            vulns = await self._cve_request(params)
            if vulns:
                return self._format_cve_results(vulns)

            cpe_partial = f"cpe:2.3:a:{vendor}:{product}"
            params = {"cpeMatchString": cpe_partial}
            if self.api_key:
                params["apiKey"] = self.api_key
            vulns = await self._cve_request(params)
            if vulns:
                return self._format_cve_results(vulns)

        params = {"keywordSearch": f"{service} {version}"}
        if self.api_key:
            params["apiKey"] = self.api_key
        vulns = await self._cve_request(params)
        return self._format_cve_results(vulns)

    @staticmethod
    def _format_cve_results(vulns: list[Any] | None) -> str:
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
                ver = match.group(2).decode("utf-8", errors="replace") if match.lastindex and match.lastindex >= 2 else "unknown"
                return svc, ver
        return None, None

    @staticmethod
    def _get_probe(port: int, ip: str) -> bytes:
        if port in {80, 8000, 8080, 8888}:
            host: str = f"[{ip}]" if ":" in ip else ip
            return f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        if port in {6379}:
            return b"PING\r\n"
        if port in {25, 587}:
            return b"EHLO scanner\r\n"
        if port in {143}:
            return b"A001 CAPABILITY\r\n"
        if port in {110}:
            return b"CAPA\r\n"
        return b"\r\n"

    @staticmethod
    def _is_greeting_port(port: int) -> bool:
        return port in GREETING_PORTS

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            ip: str, port: int, timeout: float,
                            family: int = 0) -> tuple[str | None, str | None]:
        banner: bytes = b""
        if self._is_greeting_port(port):
            try:
                banner = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except (OSError, asyncio.TimeoutError):
                pass

        if not banner:
            probe: bytes = self._get_probe(port, ip)
            try:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=timeout)
                banner = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except (OSError, asyncio.TimeoutError):
                pass

        if banner:
            svc, ver = self._parse_banner(banner)
            if svc is not None:
                return svc, ver

        if port in TLS_PORTS:
            ctx: ssl.SSLContext = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_writer: asyncio.StreamWriter | None = None
            try:
                tls_reader, tls_writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, family=family), timeout=timeout
                )
                try:
                    banner = await asyncio.wait_for(tls_reader.read(4096), timeout=timeout)
                except (OSError, asyncio.TimeoutError):
                    pass
                if not banner:
                    probe = self._get_probe(port, ip)
                    try:
                        tls_writer.write(probe)
                        await asyncio.wait_for(tls_writer.drain(), timeout=timeout)
                        banner = await asyncio.wait_for(tls_reader.read(4096), timeout=timeout)
                    except (OSError, asyncio.TimeoutError):
                        pass
                if banner:
                    return self._parse_banner(banner)
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                if tls_writer is not None:
                    try:
                        tls_writer.close()
                        await tls_writer.wait_closed()
                    except OSError:
                        pass

        return None, None

    async def _scan_port(self, target_ip: str, ip: str, port: int, timeout: float, delay: float,
                          family: int = 0) -> None:
        await asyncio.sleep(delay)
        await self._rate_limiter.acquire()

        logger.debug("Connecting to %s:%d", ip, port)
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=family), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError):
            logger.debug("Port %d: connection refused or timed out", port)
            return

        logger.debug("Port %d: connected", port)

        service = "unknown"
        version = "unknown"
        cve_output: str = ""

        try:
            async with self._ports_lock:
                self.open_ports.append(port)

            svc, ver = await self._grab_banner(reader, writer, ip, port, timeout, family)
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
                    "target": target_ip,
                    "port": port,
                    "service": service,
                    "version": version,
                    "cve": cve_output,
                })
            writer.close()
            await writer.wait_closed()

    async def scan(
        self, target_ip: str, ports: list[int] | None = None,
        port_start: int = DEFAULT_PORT_START,
        port_end: int = DEFAULT_PORT_END, timeout: float = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS, delay: float = DEFAULT_DELAY,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        family: int = 0,
    ) -> None:
        async with self._ports_lock:
            self.open_ports = []
            self.results = []

        if ports is not None:
            for p in ports:
                if not 1 <= p <= 65535:
                    logger.error("port must be between 1 and 65535, got %d", p)
                    return
        else:
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
            ip: str
            resolved_family: int
            ip, resolved_family = resolve_target(target_ip, family)
            logger.debug("Resolved %s to %s (family=%s)", target_ip, ip,
                         "IPv6" if resolved_family == socket.AF_INET6 else "IPv4")

            port_list: list[int] = ports if ports is not None else list(range(port_start, port_end + 1))
            total_ports: int = len(port_list)
            start_time: datetime = datetime.now()
            logger.info("=" * 60)
            logger.info("  Port Scanner — Target: %s", ip)
            if ports is not None:
                logger.info("  Ports: %s (%d ports)", ",".join(str(p) for p in ports), total_ports)
            else:
                logger.info("  Range: %d-%d (%d ports)", port_start, port_end, total_ports)
            logger.info("  Workers: %d | Timeout: %ss | Delay: %ss", threads, timeout, delay)
            logger.info("  Started: %s", start_time)
            logger.info("=" * 60)
            logger.info("%7s  %-14s %-8s", "PORT", "SERVICE", "VERSION")
            logger.info("-" * 60)

            sem: asyncio.Semaphore = asyncio.Semaphore(threads)

            async def _scan(port: int) -> None:
                async with sem:
                    await self._scan_port(target_ip, ip, port, timeout, delay,
                                          resolved_family)

            tasks: list[asyncio.Task[None]] = [asyncio.create_task(_scan(port))
                                                for port in port_list]

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
            logger.error("Hostname cannot be resolved: %s", target_ip)

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
