from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import socket
import sys

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
    args: argparse.Namespace = parser.parse_args()

    _setup_logging(args.output, args.verbose)

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        try:
            socket.gethostbyname(args.target)
        except socket.gaierror:
            logger.error("Invalid IP address or hostname")
            sys.exit(1)

    scanner: PortScanner = PortScanner()

    try:
        asyncio.run(scanner.scan(args.target, args.port_start, args.port_end,
                                 args.timeout, args.threads, args.delay,
                                 args.scan_timeout))
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.warning("Scan cancelled by user")
    except Exception:
        logger.exception("Unexpected error")
