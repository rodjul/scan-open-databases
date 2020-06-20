import socket
import re

mssql_payload = b'\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=nmap\r\n\x01\0\x08\0\x03\0\0\0'
match_response = [
    {"version":"Microsoft Terminal Services", "payload":b"^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x1f\x08\0\x02\0\0\0"},
    {"version":"Microsoft Terminal Services", "payload":b"^\x03\0\0\x0b\x06\xd0\0\0\x124\0$"},
    {"version":"Microsoft Terminal Services", "payload":b"^\x03\0\0\x13\x0e\xd0\0\0\x124\0"},
]

TIMEOUT = 5


def check_banner(response, ip, port):
    matched = 0
    for match in match_response:
        regex = re.compile(match['payload'])
        if regex.search(response):
            print("{ip} tcp/{port} - {banco}".format(ip=ip,port=port,banco=match['version']))
            matched = 1
            break
    
    if not matched:
        print("{ip} tcp/{port} - unkown".format(ip=ip,port=port))



def connect_host(ip,port,payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(( str(ip),int(port) ))
        s.sendall(payload)
        response = s.recv(1024)
        s.close()
        check_banner(response, ip, port)
    except ConnectionRefusedError:
        print("{ip} tcp/{port} - closed".format(ip=ip,port=port))
    except socket.timeout:
        print("{ip} tcp/{port} - no response".format(ip=ip,port=port))
    except BlockingIOError:
        print("{ip} tcp/{port} - Resource temporarily unavailable".format(ip=ip,port=port))
    
checks = [["183.15.121.206",3389]]

for check in checks:
    ip = check[0]
    port = check[1]
    connect_host(ip, port,mssql_payload)

