from __future__ import annotations

import ipaddress
import re
import socket

DEFAULT_PORT_START: int = 20
DEFAULT_PORT_END: int = 3306
DEFAULT_TIMEOUT: float = 1.0
DEFAULT_THREADS: int = 50
DEFAULT_DELAY: float = 0.0
DEFAULT_SCAN_TIMEOUT: float = 0.0
DEFAULT_MAX_RATE: float = 0.0

TIMING_PROFILES: dict[int, dict[str, float | int]] = {
    0: {"timeout": 5.0, "threads": 5, "delay": 5.0},
    1: {"timeout": 2.0, "threads": 10, "delay": 1.0},
    2: {"timeout": 1.0, "threads": 25, "delay": 0.1},
    3: {"timeout": 1.0, "threads": 50, "delay": 0.0},
    4: {"timeout": 0.5, "threads": 100, "delay": 0.0},
    5: {"timeout": 0.3, "threads": 200, "delay": 0.0},
}

PORTS_COMMON: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
]

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
    re.compile(rb"220[\s-]\S+\s+ESMTP\s+(Postfix|Exim|Sendmail|Courier)\b", re.IGNORECASE),
    re.compile(rb"\* OK\s+\[.*?\]\s+(Dovecot|Cyrus)\s+", re.IGNORECASE),
    re.compile(rb"\+OK\s+(Dovecot)\s+", re.IGNORECASE),
    re.compile(rb"HTTP/1\.[01]\s+\d+\s+(\w+)"),
    re.compile(rb"(\w[\w.-]+)/([\d.]+)"),
    re.compile(rb"(\w[\w.-]+)\s+v?([\d.]+)"),
]

TLS_PORTS: set[int] = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 8883, 8888}

GREETING_PORTS: set[int] = {21, 22, 25, 110, 143, 587}

CPE_MAP: dict[str, tuple[str, str]] = {
    "OpenSSH": ("openbsd", "openssh"),
    "Apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "Postfix": ("postfix", "postfix"),
    "ProFTPD": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "Dovecot": ("dovecot", "dovecot"),
    "Exim": ("exim", "exim"),
    "Sendmail": ("sendmail", "sendmail"),
    "Courier": ("courier", "courier"),
    "MySQL": ("oracle", "mysql"),
    "Redis": ("redis", "redis"),
    "OpenSSL": ("openssl", "openssl"),
    "Python": ("python", "python"),
    "Node.js": ("nodejs", "node.js"),
    "Microsoft": ("microsoft", "iis"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "Cyrus": ("cyrus", "cyrus_imap"),
    "FileZilla": ("filezilla_project", "filezilla"),
    "Pure-FTPd": ("pureftpd", "pure-ftpd"),
}


def expand_targets(specs: list[str]) -> list[str]:
    targets: list[str] = []
    for spec in specs:
        if "/" in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
            except ValueError:
                targets.append(spec)
        else:
            targets.append(spec)
    seen: set[str] = set()
    result: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def parse_port_spec(spec: str) -> list[int]:
    normalized = spec.strip().lower()
    if normalized == "common":
        return list(PORTS_COMMON)
    if normalized == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str.strip())
            end = int(end_str.strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port range values must be 1-65535, got {part}")
            if start > end:
                raise ValueError(f"Port range start > end: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port must be 1-65535, got {port}")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports specified")
    return sorted(ports)


def resolve_target(target: str, family: int = 0) -> tuple[str, int]:
    try:
        ipaddress.ip_address(target)
        addr = target
        fam: int = socket.AF_INET6 if ":" in target else socket.AF_INET
        return addr, fam
    except ValueError:
        pass

    families: list[int] = [socket.AF_INET6, socket.AF_INET] if family == 0 else [family]
    for fam in families:
        try:
            addrinfo = socket.getaddrinfo(target, 0, family=fam, type=socket.SOCK_STREAM)
            return str(addrinfo[0][4][0]), int(addrinfo[0][0])
        except socket.gaierror:
            continue
    raise socket.gaierror(f"Could not resolve {target}")
