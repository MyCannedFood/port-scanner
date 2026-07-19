import socket
import ipaddress
import argparse
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock

DEFAULT_PORT_START = 20
DEFAULT_PORT_END = 3306
DEFAULT_TIMEOUT = 1
DEFAULT_THREADS = 50
DEFAULT_DELAY = 0

SERVICE_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

print_lock = Lock()
scan_count = 0
open_ports = []
progress_lock = Lock()

def get_cve_text(service, version):
    try:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}",
            timeout=10
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return f"         [!] CVE lookup failed: {e}\n"

    try:
        data = response.json()
    except ValueError as e:
        return f"         [!] Failed to parse CVE response: {e}\n"

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return "         No CVEs found\n"

    lines = [f"         Found {len(vulns)} CVE(s):\n"]
    for item in vulns[:3]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        desc = "N/A"
        if "descriptions" in cve:
            for d in cve["descriptions"]:
                if d.get("lang") == "en":
                    desc = d.get("value", "N/A")
                    break
        lines.append(f"           - {cve_id}: {desc[:120]}\n")
    return "".join(lines)

def scan_port(ip, port, timeout, delay):
    global scan_count
    time.sleep(delay)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result = sock.connect_ex((ip, port))

    with progress_lock:
        scan_count += 1

    if result != 0:
        sock.close()
        return

    with progress_lock:
        open_ports.append(port)

    try:
        sock.send(b"\r\n")
        banner = sock.recv(1024)
    except (socket.timeout, OSError):
        sock.close()
        return

    service = "unknown"
    version = "unknown"

    try:
        parts = banner.split(b"-")
        service = parts[2].split(b"_")[0].decode("utf-8", errors="replace")
        version_raw = parts[2].split(b"_")[1]
        version_raw = version_raw.split(b" ")[0]
        version_raw = version_raw.split(b"p")[0]
        ver_parts = version_raw.split(b".")
        version = f"{ver_parts[0].decode('utf-8', errors='replace')}.{ver_parts[1].decode('utf-8', errors='replace')}"
    except (IndexError, UnicodeDecodeError, NameError):
        pass

    if service == "unknown":
        service = SERVICE_PORTS.get(port, "unknown")

    cve_output = ""
    if service != "unknown":
        cve_output = get_cve_text(service, version)

    with print_lock:
        print(f"  OPEN  {port:>5}  {service:<14} {version:<8}")
        if cve_output:
            print(cve_output, end="")

    sock.close()

def port_scan(target_ip, port_start=DEFAULT_PORT_START, port_end=DEFAULT_PORT_END,
              timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS, delay=DEFAULT_DELAY):
    global scan_count, open_ports
    scan_count = 0
    open_ports = []

    try:
        ip = socket.gethostbyname(target_ip)

        total_ports = port_end - port_start + 1
        start_time = datetime.now()
        print("=" * 60)
        print(f"  Port Scanner — Target: {ip}")
        print(f"  Range: {port_start}-{port_end} ({total_ports} ports)")
        print(f"  Workers: {threads} | Timeout: {timeout}s | Delay: {delay}s")
        print(f"  Started: {start_time}")
        print("=" * 60)
        print(f"{'PORT':>7}  {'SERVICE':<14} {'VERSION':<8}")
        print("-" * 60)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, ip, port, timeout, delay): port
                       for port in range(port_start, port_end + 1)}
            for _ in tqdm(as_completed(futures), total=total_ports,
                          desc="Scanning", unit="port", ncols=80):
                pass

        end_time = datetime.now()
        print("=" * 60)
        print(f"  Scan complete: {len(open_ports)}/{total_ports} ports open")
        print(f"  Duration: {end_time - start_time}")
        print(f"  Finished: {end_time}")
        print("=" * 60)

    except socket.gaierror:
        print("Hostname cannot be resolved")

    except socket.error:
        print("Could not connect to the server")

def main():
    parser = argparse.ArgumentParser(description="Port Scanner with banner grabbing and CVE lookup")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORT_START,
                        help=f"Start port (default: {DEFAULT_PORT_START})")
    parser.add_argument("--port-end", type=int, default=DEFAULT_PORT_END,
                        help=f"End port (default: {DEFAULT_PORT_END})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of worker threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between scans in seconds (default: {DEFAULT_DELAY})")
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        try:
            socket.gethostbyname(args.target)
        except socket.gaierror:
            print("Invalid IP address or hostname")
            return

    port_scan(args.target, args.port_start, args.port_end, args.timeout, args.threads, args.delay)

if __name__ == "__main__":
    main()
