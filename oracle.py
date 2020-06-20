import socket
import re

# oracle_payload = b'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))'
# oracle_payload = b'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))'
#https://svn.nmap.org/nmap/scripts/oracle-tns-version.nse
oracle_payload = b'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x004\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))'

#https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py
match_response = [
    {"version":"Oracle TNS Listener", "payload": b'\(ERROR_STACK=\(ERROR=\(CODE='},
    {"version":"Oracle TNS Listener", "payload": b'\(ADDRESS=\(PROTOCOL='},
    {"version":"Oracle TNS Listener", "payload": b'^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1189\)\(ERROR_STACK=\(ERROR=\(CODE=1189\)\(EMFI=4\)\)'},
    {"version":"Oracle TNS Listener", "payload": b'^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1194\)\(ERROR_STACK=\(ERROR=\(CODE=1194\)\(EMFI=4\)\)\)\)'},
    {"version":"Oracle TNS listener", "payload": b'^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(ERR=12504\)\)\0'},
    {"version":"Oracle TNS Listener", "payload": b'^\0.\0\0[\x02\x04]\0\0\0.*\([ABD-Z]'},
    {"version":"Oracle Database", "payload": b'^\0\x20\0\0\x02\0\0\0\x016\0\0\x08\0\x7f\xff\x01\0\0\0\0\x20'},
    {"version":"Oracle Database", "payload": b'^\+\0\0\0$'},
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
    

checks = [["192.168.15.1",1234]]

for check in checks:
    ip = check[0]
    port = check[1]
    connect_host(ip, port,oracle_payload)