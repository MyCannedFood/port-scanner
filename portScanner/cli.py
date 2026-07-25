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
    TIMING_PROFILES,
    PortScanner,
    expand_targets,
    logger,
    parse_port_spec,
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


def _read_targets_from_file(path: str) -> list[str]:
    try:
        with open(path) as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not lines:
            logger.error("No targets found in '%s'", path)
            sys.exit(1)
        return lines
    except OSError as e:
        logger.error("Cannot read input file '%s': %s", path, e)
        sys.exit(1)


def _validate_target(target: str) -> None:
    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            socket.getaddrinfo(target, 0, type=socket.SOCK_STREAM)
        except socket.gaierror:
            logger.error("Invalid IP address or hostname: %s", target)
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Port Scanner with banner grabbing and CVE lookup")
    parser.add_argument("target", nargs="?", help="Target IP address or hostname (or CIDR)")
    parser.add_argument("-iL", "--input-list", help="File containing target hosts/networks (one per line)")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORT_START,
                        help=f"Start port (default: {DEFAULT_PORT_START})")
    parser.add_argument("--port-end", type=int, default=DEFAULT_PORT_END,
                        help=f"End port (default: {DEFAULT_PORT_END})")
    parser.add_argument("--timeout", type=float, default=None,
                        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--threads", type=int, default=None,
                        help=f"Number of concurrent tasks (default: {DEFAULT_THREADS})")
    parser.add_argument("--delay", type=float, default=None,
                        help=f"Delay between scans in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("-T", "--timing", type=int, choices=range(0, 6), default=None,
                        help="Timing profile 0-5 (paranoid to insane)")
    parser.add_argument("-p", "--ports",
                        help="Ports to scan (e.g. '22,80,443', '1-1000', 'common', 'all')")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--scan-timeout", type=float, default=DEFAULT_SCAN_TIMEOUT,
                        help=f"Total scan timeout in seconds, 0 = no limit (default: {DEFAULT_SCAN_TIMEOUT})")
    parser.add_argument("-6", "--ipv6", action="store_true",
                        help="Force IPv6 resolution")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug-level logging for troubleshooting")
    parser.add_argument("--format", "-f", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    args: argparse.Namespace = parser.parse_args()

    if not args.target and not args.input_list:
        logger.error("A target or --input-list is required")
        sys.exit(1)

    port_list: list[int] | None = None
    if args.ports:
        try:
            port_list = parse_port_spec(args.ports)
        except ValueError as e:
            logger.error("Invalid port specification: %s", e)
            sys.exit(1)

    raw_targets: list[str] = []
    if args.target:
        raw_targets.append(args.target)
    if args.input_list:
        raw_targets.extend(_read_targets_from_file(args.input_list))

    targets: list[str] = expand_targets(raw_targets)
    for t in targets:
        _validate_target(t)

    if args.timing is not None:
        profile: dict[str, float | int] = TIMING_PROFILES[args.timing]
        args.timeout = profile["timeout"] if args.timeout is None else args.timeout
        args.threads = profile["threads"] if args.threads is None else args.threads
        args.delay = profile["delay"] if args.delay is None else args.delay
    if args.timeout is None:
        args.timeout = DEFAULT_TIMEOUT
    if args.threads is None:
        args.threads = DEFAULT_THREADS
    if args.delay is None:
        args.delay = DEFAULT_DELAY

    _setup_logging(args.output if args.format == "text" else None, args.verbose)

    all_results: list[dict[str, str | int]] = []
    total_open: int = 0
    scan_start: float = time.monotonic()

    for i, target in enumerate(targets):
        logger.info("%sScanning target %d/%d: %s",
                     "\n" if i > 0 else "", i + 1, len(targets), target)
        scanner = PortScanner()

        try:
            asyncio.run(scanner.scan(
                target, ports=port_list,
                port_start=args.port_start, port_end=args.port_end,
                timeout=args.timeout, threads=args.threads, delay=args.delay,
                scan_timeout=args.scan_timeout,
                family=socket.AF_INET6 if args.ipv6 else 0,
            ))
        except (KeyboardInterrupt, asyncio.CancelledError):
            logger.warning("Scan cancelled by user")
            break
        except Exception:
            logger.exception("Unexpected error scanning %s", target)
            continue

        all_results.extend(scanner.results)
        total_open += len(scanner.open_ports)

    scan_duration: float = time.monotonic() - scan_start

    if args.format != "text":
        _write_structured_output(all_results, args, scan_duration, port_list, targets)


def _write_structured_output(
    results: list[dict[str, str | int]], args: argparse.Namespace, duration: float,
    port_list: list[int] | None, targets: list[str],
) -> None:
    data: dict[str, object] = {
        "targets": targets,
        "port_start": args.port_start,
        "port_end": args.port_end,
        "ports": port_list if port_list else list(range(args.port_start, args.port_end + 1)),
        "total_ports": len(port_list) if port_list else args.port_end - args.port_start + 1,
        "duration_seconds": round(duration, 2),
        "open_ports_count": len(results),
        "results": results,
    }

    if args.format == "json":
        output: str = json.dumps(data, indent=2, default=str)
    else:
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=["target", "port", "service", "version", "cve"])
        writer.writeheader()
        writer.writerows(results)
        output = buf.getvalue()

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output)
        except OSError as e:
            logger.error("Cannot write output file '%s': %s", args.output, e)
    else:
        print(output)
