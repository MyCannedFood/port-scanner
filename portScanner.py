import socket
from datetime import datetime

target_ip = input("Enter the target IP address: ")

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
                version = version[0].decode()
                
                print(f"{service} {version}")
                print("Port {}: open".format(port))

            sock.close()

    except socket.gaierror:
        print("Hostname cannot be resolved")

    except socket.error:
        print("Could not connect to the server")

port_scan(target_ip)
