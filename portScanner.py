import socket
import ipaddress
import argparse
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

DEFAULT_PORT_START = 20
DEFAULT_PORT_END = 3306
DEFAULT_TIMEOUT = 1
DEFAULT_THREADS = 50

print_lock = Lock()

def cve_lookup(service, version):
    try:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}",
            timeout=10
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"  [!] CVE lookup failed: {e}")
        return

    try:
        data = response.json()
    except ValueError as e:
        print(f"  [!] Failed to parse CVE response: {e}")
        return

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("  No CVEs found")
        return

    print(f"  Found {len(vulns)} CVE(s):")
    for item in vulns[:3]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        desc = "N/A"
        if "descriptions" in cve:
            for d in cve["descriptions"]:
                if d.get("lang") == "en":
                    desc = d.get("value", "N/A")
                    break
        print(f"    - {cve_id}: {desc[:120]}")

def scan_port(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result = sock.connect_ex((ip, port))
    if result != 0:
        sock.close()
        return

    with print_lock:
        print("Port {}: open".format(port))

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

    with print_lock:
        print(f"  Service: {service} {version}")

    if service != "unknown":
        cve_lookup(service, version)

    sock.close()

def port_scan(target_ip, port_start=DEFAULT_PORT_START, port_end=DEFAULT_PORT_END,
              timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    try:
        ip = socket.gethostbyname(target_ip)

        print(f"Scanning {ip} from port {port_start} to {port_end}")
        print(f"Workers: {threads} | Timeout: {timeout}s")
        print("Time started: ", datetime.now())

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, ip, port, timeout): port
                       for port in range(port_start, port_end + 1)}
            for future in as_completed(futures):
                pass

        print("Time finished: ", datetime.now())

    except socket.gaierror:
        print("Hostname cannot be resolved")

    except socket.error:
        print("Could not connect to the server")

def main():
    parser = argparse.ArgumentParser(description="Port Scanner with banner grabbing and CVE lookup")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORT_START,
                        help=f"Start port (default: {DEFAULT_PORT_START})")
    parser.add_argument("--port-end", type=int, default=DEFAULT_PORT_END,
                        help=f"End port (default: {DEFAULT_PORT_END})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of worker threads (default: {DEFAULT_THREADS})")
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.target_ip)
    except ValueError:
        print("Invalid IP address format")
        return

    port_scan(args.target_ip, args.port_start, args.port_end, args.timeout, args.threads)

if __name__ == "__main__":
    main()
