#All in one (network reachability checker, Port scanner, dns lookup, simple log analyzer)

import time
import socket

Hosts = [
    "google.com", "facebook.com", "twitter.com",
    "github.com", "stackoverflow.com", "nonexistent.domain",
    "1.1.1.1"]

port = 80
timeout = 3

def host_reachability(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.error:
        return False


host_reachability