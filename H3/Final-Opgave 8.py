import socket


def port_scanner ():
    hosts = ['20.91.198.208']
    ports = [22, 80, 443, 8081]
    timeout = 2 

    for host in hosts:
        print(f"Scanning host: {host}")
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) #DEFINE TCP SOCKET
            sock.settimeout(timeout)

            try:
                sock.connect((host, port))
                print(f"  ✓ Port {port} is open on {host}")
            except (socket.timeout, socket.error):
                print(f"  ✗ Port {port} is closed on {host}")
            finally:
                sock.close()
        print() 
port_scanner()