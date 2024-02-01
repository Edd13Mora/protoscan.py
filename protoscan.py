import socket
import telnetlib
import argparse
from ipaddress import ip_network
from termcolor import colored
import requests

# Function to check for open port
def check_port_open(ip, port, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error as err:
        print(colored(f"Couldn't connect to {ip}:{port} - {err.strerror}", "red"))
        return False

# Function to attempt anonymous login via Telnet
def check_anonymous_login(ip, port=23, timeout=5):
    try:
        telnet = telnetlib.Telnet(ip, port, timeout)
        telnet.read_until(b"login: ")
        telnet.write(b"anonymous\n")
        telnet.read_until(b"Password: ")
        telnet.write(b"\n")
        response = telnet.read_some().decode('ascii')
        telnet.close()
        return "Login incorrect" not in response
    except Exception as e:
        print(colored(f"Telnet error on {ip}:{port} - {e}", "red"))
        return False

# Function to check for HTTP/HTTPS service on multiple ports
def check_web_services(ip, ports, protocol='http', timeout=3):
    for port in ports:
        url = f"{protocol}://{ip}:{port}"
        try:
            response = requests.get(url, timeout=timeout)
            print(colored(f"{ip} - {protocol.upper()} on port {port} open - Status code: {response.status_code}", "green"))
        except requests.ConnectionError:
            print(colored(f"{ip} - {protocol.upper()} on port {port} - Service not available or Connection refused", "red"))
        except requests.Timeout:
            print(colored(f"{ip} - {protocol.upper()} on port {port} - Request timed out", "red"))
        except requests.RequestException as e:
            print(colored(f"{ip} - {protocol.upper()} on port {port} - An error occurred: {str(e)}", "red"))

# Main function to scan a subnet for specified service
def scan_subnet(subnet, service, ports):
    print(colored(f"Scanning subnet: {subnet} for {service.upper()} service", "blue"))
    for ip in ip_network(subnet, strict=False).hosts():
        ip_str = str(ip)
        print(colored(f"Checking {ip_str}...", "yellow"), end="\r")

        try:
            if service.lower() == 'telnet':
                for port in ports:
                    if check_port_open(ip_str, port):
                        print(colored(f"Telnet on port {port} open!", "green"), end=" ")
                        if check_anonymous_login(ip_str, port):
                            print(colored("Anonymous login possible!", "red"))
                        else:
                            print(colored("No anonymous login.", "cyan"))
                    else:
                        print(colored(f"Telnet on port {port} closed.", "cyan"))

            elif service.lower() in ['http', 'https']:
                check_web_services(ip_str, ports, service)

        except Exception as e:
            print(colored(f"Error scanning {ip_str}: {e}", "red"))
            continue  # This ensures the loop continues even after an error

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Service Scanner")
    parser.add_argument("subnet", help="IP subnet in CIDR notation, e.g., 192.168.1.0/24")
    parser.add_argument("service", choices=['telnet', 'http', 'https'], help="Service to scan for (telnet, http, or https)")
    parser.add_argument("--port", nargs='+', type=int, help="Optional port numbers for the service, separated by space", default=None)
    args = parser.parse_args()

    # Default ports for services if not specified
    if not args.port:
        if args.service.lower() == 'http':
            args.port = [80]
        elif args.service.lower() == 'https':
            args.port = [443]
        elif args.service.lower() == 'telnet':
            args.port = [23]

    scan_subnet(args.subnet, args.service, args.port)
