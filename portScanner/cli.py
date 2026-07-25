from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import socket
import sys
import time
from io import StringIO

from portScanner.scanner import (
    DEFAULT_DELAY,
    DEFAULT_PORT_END,
    DEFAULT_PORT_START,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    PortScanner,
    logger,
)


def _setup_logging(output_file: str | None = None, verbose: bool = False) -> None:
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter("%(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if output_file:
        try:
            file_handler = logging.FileHandler(output_file, mode="w")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as e:
            logger.error("Cannot open output file '%s': %s", output_file, e)
            sys.exit(1)


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
    parser.add_argument("--scan-timeout", type=float, default=DEFAULT_SCAN_TIMEOUT,
                        help=f"Total scan timeout in seconds, 0 = no limit (default: {DEFAULT_SCAN_TIMEOUT})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug-level logging for troubleshooting")
    parser.add_argument("--format", "-f", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    args: argparse.Namespace = parser.parse_args()

    _setup_logging(args.output if args.format == "text" else None, args.verbose)

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        try:
            socket.gethostbyname(args.target)
        except socket.gaierror:
            logger.error("Invalid IP address or hostname")
            sys.exit(1)

    scanner: PortScanner = PortScanner()
    scan_start: float = time.monotonic()

    try:
        asyncio.run(scanner.scan(args.target, args.port_start, args.port_end,
                                 args.timeout, args.threads, args.delay,
                                 args.scan_timeout))
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.warning("Scan cancelled by user")
    except Exception:
        logger.exception("Unexpected error")

    scan_duration: float = time.monotonic() - scan_start

    if args.format != "text":
        _write_structured_output(scanner, args, scan_duration)


def _write_structured_output(
    scanner: PortScanner, args: argparse.Namespace, duration: float
) -> None:
    data: dict[str, object] = {
        "target": args.target,
        "port_start": args.port_start,
        "port_end": args.port_end,
        "total_ports": args.port_end - args.port_start + 1,
        "duration_seconds": round(duration, 2),
        "open_ports_count": len(scanner.open_ports),
        "results": scanner.results,
    }

    if args.format == "json":
        output: str = json.dumps(data, indent=2, default=str)
    else:
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=["port", "service", "version", "cve"])
        writer.writeheader()
        writer.writerows(scanner.results)
        output = buf.getvalue()

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output)
        except OSError as e:
            logger.error("Cannot write output file '%s': %s", args.output, e)
    else:
        print(output)
