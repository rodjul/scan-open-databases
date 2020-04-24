import socket
import re

postgree_payload = b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x53\x61\x6d\x62\x61\x00\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
match_response = [
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L[0-9]+\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\\\postmaster\\\\postmaster\.c\0L[0-9]+\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.SFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2004\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L[0-9]+\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\\\postmaster\\\\postmaster\.c\0L[0-9]+\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst\xc3\xbctztes Frontend-Protokoll 65363\.19778: Server unterst\xc3\xbctzt 1\.0 bis 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst.{1,2}tztes Frontend-Protokoll 65363\.19778: Server unterst.{1,2}tzt 1\.0 bis 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\xc3\xa9e de l'interface 65363\.19778: le serveur supporte de 1\.0 \xc3\xa0 3\.0\0Fpostmaster\.c\0L\d+\0"},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\?e de l'interface 65363\.19778 : le serveur supporte de 1\.0 \?\n3\.0\0Fpostmaster\.c\0L1621\0RProcessStartupPacket\0\0"},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\?e de l'interface 65363\.19778 : le serveur supporte de 1\.0 \?\n3\.0\0Fpostmaster\.c\0L1626\0RProcessStartupPacket\0\0$"},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support[e\xe9]e de l'interface 65363\.19778: le serveur supporte de 1\.0 [a\xe0] 3\.0\0Fpostmaster\.c\0L\d+\0"},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0Mprotocole non support\xe9e de l'interface 65363\.19778: le serveur supporte de 1\.0 \xe0 3\.0\0Fpostmaster\.c\0L\d+\0"},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363\.19778 no est..? soportado: servidor soporta 1\.0 hasta 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363\.19778 no est\? permitido: servidor permite 1\.0 hasta 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mprotocolo 65363\.19778 n\xe3o \xe9 suportado: servidor suporta 1\.0 a 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mprotocolo do cliente 65363\.19778 n.{4,6} suportado: servidor suporta 1\.0 a 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M\xd0\xbd\xd0\xb5\xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd0\xbc\xd1\x8b\xd0\xb9 \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9 \xd0\xbf\xd1\x80\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba\xd0\xbe\xd0\xbb 65363\.19778: \xd1\x81\xd0\xb5\xd1\x80\xd0\xb2\xd0\xb5\xd1\x80 \xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd1\x82 \xd0\xbe\xd1\x82 1\.0 \xd0\xb4\xd0\xbe 3\.0\0Fpostmaster\.c\0L\d+\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\? 65363\.19778; \?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\?\? 1\.0 - 3\.0 \0Fpostmaster\.c\0L1695\0RProcessStartupPacket\0\0$'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0\xb1S\xec\xb9\x98'},
    {"version":"Postgre SQL","payload": b"^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support.{1,2}e de l'interface 65363"},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst.*?Frontend-Protokoll 65363\.19778:'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M\xe3\x83\x95\xe3\x83\xad\xe3\x83\xb3\xe3\x83\x88\xe3\x82\xa8\xe3\x83\xb3\xe3\x83\x89\xe3\x83\x97\xe3\x83\xad\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xab'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0Fpostmaster\.c\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0F\.\\src\\backend\\\\postmaster\\\\postmaster\.c\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0C0A000\0Munsupported frontend protocol 65363'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0F\.\\src\\backend\\\\postmaster\\\\postmaster\.c\0'},
    {"version":"Postgre SQL","payload": b'^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0Munsupported frontend protocol 65363'}
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

