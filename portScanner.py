import socket
import ipaddress
import requests
from datetime import datetime

def cve_lookup(service, version):
    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}")

    for items in response.json()["vulnerabilities"]:
        print(items)

    print(response.json())

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
                sock.send(b"\r\n")
                
                response = sock.recv(1024)
                response = response.split(b"-")
                response = response[2].split(b"_")

                service = response[0].decode()
                
                version = response[1].split(b" ")
                version = version[0].split(b"p")
                version = version[0].split(b".")
                version = f"{version[0].decode()}.{version[1].decode()}"
                
                print(f"{service} {version}")
                print("Port {}: open".format(port))

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
