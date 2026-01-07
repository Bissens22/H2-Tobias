#All in one (network reachability checker, Port scanner, dns lookup, simple log analyzer)

import time
import socket

hosts = [
    "google.com", "facebook.com", "twitter.com",
    "github.com", "stackoverflow.com", "nonexistent.domain",
    "1.1.1.1"]
# Define ports to check
port = 80
secure_port = 443

timeout = 3 # connection timeout

def host_reachability ():
    # Print header for the reachability check section
    print("\n" + "="*70)
    print("HOST REACHABILITY CHECK")
    print("="*70 + "\n")
    
    # Loop through each host in the hosts list
    for host in hosts:
        print(f"Testing {host}...")
        
        # Test port 80 (HTTP)
        start_time = time.time()  # Record start time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
        sock.settimeout(timeout)  # Set connection timeout

        try:
            sock.connect((host, port))  # Attempt to connect to host on port 80
            end_time = time.time()  # Record end time
            print(f"  ✓ Port {port:3d} (HTTP)  | Reachable | {end_time - start_time:.2f}s")  # Print success message with response time
        except (socket.timeout, socket.error):  # Catch timeout or connection errors
            print(f"  ✗ Port {port:3d} (HTTP)  | Unreachable")  # Print failure message
        finally:
            sock.close()  # Always close the socket           

        # Test port 443 (HTTPS)
        start_time = time.time()  # Record start time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
        sock.settimeout(timeout)  # Set connection timeout

        try:
            sock.connect((host, secure_port))  # Attempt to connect to host on port 443
            end_time = time.time()  # Record end time
            print(f"  ✓ Port {secure_port:3d} (HTTPS) | Reachable | {end_time - start_time:.2f}s")  # Print success message with response time
        except (socket.timeout, socket.error):  # if it timeout or errors it makes another output
            print(f"  ✗ Port {secure_port:3d} (HTTPS) | Unreachable") 
        finally:
            sock.close()  # Always close the socket
        
        print()  # Print blank line for readability
    
    retry_option()
#------------------------------------------------------------------------------
def host_reachability_from_file():
    for host in open("hosts.txt", "r"):
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            end_time = time.time()
            print(f"Host {host.strip()} is reachable on port {port}. Response time: {end_time - start_time:.2f} seconds")
        except (socket.timeout, socket.error):
            print(f"Host {host.strip()} is not reachable on port {port}.")
        finally:
            sock.close()


#------------------------------------------------------------------------------
def dns_lookup ():
    for host in hosts:
        try:
            ip_address = socket.gethostbyname(host)
            print(f" ✓ DNS Lookup: {host} has the following ip {ip_address}")
        except socket.gaierror:
            print(f" ✗ DNS Lookup failed for {host}")

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
#------------------------------------------------------------------------------

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