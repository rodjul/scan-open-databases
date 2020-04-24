import socket
import re

ibm_db2_payload = b'\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0SQLDB2RA\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f'
match_response = [
    {"version":"IBM DB2 Database Server", "payload": b'(?<=.)DB2/([^\0]+)\0\0\0\0\0\0\0\0.{1,4}\0\0\0\0\0\0\0SQL0(\d)(\d\d)(\d+)'},
    {"version":"IBM DB2 Database Server", "payload": b'^\0\xa9\x10..\x01\0\0SQLDB2RA\x01\0\x05\0.{10,13}SQLCA'},
    {"version":"IBM DB2 Database Server", "payload": b'^\0\xa9\x10..\x01\x0e\x10SQLDB2RA\x01\0\x05\0.{10,13}SQLCA'},
]

TIMEOUT = 2


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
        s.connect(( str(ip),int(port) ))
        s.settimeout(TIMEOUT)
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
    


# for check in checks:
#     ip = check[0]
#     port = check[1]
#     connect_host(ip, port,mssql_payload)

