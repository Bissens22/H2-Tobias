#All in one (network reachability checker, Port scanner, dns lookup, simple log analyzer)

import time
import socket

hosts = [
    "google.com", "facebook.com", "twitter.com",
    "github.com", "stackoverflow.com", "nonexistent.domain",
    "1.1.1.1"]

port = 80
timeout = 3

def host_reachability ():
    for host in hosts:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            end_time = time.time()
            print(f"Host {host} is reachable on port {port}. Response time: {end_time - start_time:.2f} seconds")
        except (socket.timeout, socket.error):
            print(f"Host {host} is not reachable on port {port}.")
        finally:
            sock.close()
    
    retry_option()
#------------------------------------------------------------------------------

def dns_lookup ():
    for host in hosts:
        try:
            ip_address = socket.gethostbyname(host)
            print(f"DNS Lookup: {host} -> {ip_address}")
        except socket.gaierror:
            print(f"DNS Lookup failed for {host}")

    retry_option()

#------------------------------------------------------------------------------

def retry_option():   
    retry = input("do you want to continue and do another test? (type yes to continue, no to exit")
    if retry == "yes":
        options()
    elif retry == "no":
        print("exiting program")
        return
    else:
        print("invalid input, exiting program")
        return

def options ():
    print("Select an option:")
    print("1. Check Host Reachability")
    print("1.1 Check Host Reachablity with hosts in a .txt file")
    print("2. DNS Lookup")

    while True:
        choice = input("Enter your choice (1, 1.1, 2): ")
        if choice == "1":
            host_reachability()
            break
        elif choice == "1.1":
            host_reachability_from_file()
            break
        elif choice == "2":
            dns_lookup()
            break

        else:
            print("Invalid choice. Please enter 1 or 2.")

options()