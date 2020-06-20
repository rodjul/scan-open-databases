import socket
import re

mssql_payload = b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00'
match_response = [
    {"version":"Microsoft SQL Server", "payload_hex":"04010025000001", "payload":b"^\x04\x01\x00\x25\x00\x00\x01"},
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
    
checks = [["192.168.15.1",1234]]

for check in checks:
    ip = check[0]
    port = check[1]
    connect_host(ip, port,mssql_payload)

