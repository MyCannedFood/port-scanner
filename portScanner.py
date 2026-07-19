import socket
import ipaddress
import requests
from datetime import datetime

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

def port_scan(target_ip):
    try:
        ip = socket.gethostbyname(target_ip)

        print("Scanning the target ", ip)
        print("Time started: ", datetime.now())

        for port in range(20, 3306):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:
                print("Port {}: open".format(port))

                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024)
                except (socket.timeout, OSError):
                    continue

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

                print(f"  Service: {service} {version}")

                if service != "unknown":
                    cve_lookup(service, version)

            sock.close()

    except socket.gaierror:
        print("Hostname cannot be resolved")

    except socket.error:
        print("Could not connect to the server")

def main():
    target_ip = input("Enter the target IP address: ")

    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print("Invalid IP address format")
        return

    port_scan(target_ip)

if __name__ == "__main__":
    main()
