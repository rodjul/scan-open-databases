import socket
import re
import ipaddress
import threading
import multiprocessing
from itertools import product,repeat

MAX_THREADS = 20
TIMEOUT = 1

verbose_type = 0 # 1 -> show all outputs, 0 -> only open


mysql_payload = b''
match_response = [
    {"version":"MySQL", "payload": b'^\x10\0\0\x01\xff\x13\x04Bad handshake$'},
    {"version":"MySQL", "payload": b'^.\0\0\0\xff..Host .* is not allowed to connect to this MySQL server$'},
    {"version":"MySQL", "payload": b'^.\0\0\0\xff..Host .* is not allowed to connect to this MariaDB server$'},
    {"version":"MySQL", "payload": b'^.\0\0\0\xff..Too many connections'},
    {"version":"MySQL", "payload": b'^.\0\0\0\xff..Host .* is blocked because of many connection errors'},
    {"version":"MySQL", "payload": b"^.\0\0\0\xff..Le h\xf4te '[-.\w]+' n'est pas authoris\xe9 \xe0 se connecter \xe0 ce serveur MySQL$"},
    {"version":"MySQL", "payload": b"^.\0\0\0\xff..Host hat keine Berechtigung, eine Verbindung zu diesem MySQL Server herzustellen\."},
    {"version":"MySQL", "payload": b"^.\0\0\0\xff..Host '[-\w_.]+' hat keine Berechtigung, sich mit diesem MySQL-Server zu verbinden"},
    {"version":"MySQL", "payload": b"^.\0\0\0\xff..Al sistema '[-.\w]+' non e` consentita la connessione a questo server MySQL$"},
    {"version":"MySQL", "payload": b"^.\0\0\0...Servidor '[-.\w]+' est\xe1 bloqueado por muchos errores de conexi\xf3n\.  Desbloquear con 'mysqladmin flush-hosts'"},
    {"version":"MySQL", "payload": b"^.\0\0\0...'Host' '[-.\w]+' n\xe3o tem permiss\xe3o para se conectar com este servidor MySQL"},
    {"version":"MariaDB", "payload": b'^.\0\0\0\x0a(5\.[-_~.+:\w]+MariaDB-[-_~.+:\w]+~bionic)\0'},
    {"version":"MariaDB", "payload": b'^.\0\0\0\x0a(5\.[-_~.+:\w]+MariaDB-[-_~.+:\w]+)\0'},
    {"version":"MySQL", "payload": b'^.\0\0\0.(3\.[-_~.+\w]+)\0.*\x08\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0$'},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(3\.[-_~.+\w]+)\0...\0'},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(4\.[-_~.+\w]+)\0'},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(5\.[-_~.+\w]+)\0'},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(6\.[-_~.+\w]+)\0...\0'},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(8\.[-_~.+\w]+)\0...\0'},
    {"version":"MySQL", "payload": b"^.\0\0\0\xffj\x04'[\d.]+' .* MySQL"},
    {"version":"MySQL", "payload": b'^.\0\0\0\x0a(0[\w._-]+)\0| p/MySQL instance manager/ v/$1/ cpe:/a:mysql:mysql:$1/'},
    {"version":"MySQL", "payload": b'^\x19\x00\x00\x00\x0a'},
    {"version":"MySQL", "payload": b'^\x2c\x00\x00\x00\x0a'},
    {"version":"MySQL", "payload": b'^.\0\0\0\xff..'},
]



def get_list_of_ips(iprange):
    return [str(ip) for ip in ipaddress.IPv4Network(iprange)]

def logging(msg):
    if verbose_type == 1:
        print(msg)

def check_banner(response, ip, port):
    global match_response
    # print(response)
    matched = 0
    for match in match_response:
        regex = re.compile(match['payload'])
        if regex.search(response):
            print("{ip},tcp/{port}, {banco}".format(ip=ip,port=port,banco=match['version']))
            matched = 1
            break
    
    if not matched:
        print("{ip},tcp/{port},unkown".format(ip=ip,port=port))


def connect_host(ip,port,payload):
# def connect_host(ip):
    global TIMEOUT
    logging("Testing: {ip},tcp/{port}".format(ip=ip,port=port))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(( str(ip),int(port) ))
        s.sendall(payload)
        response = s.recv(1024)
        s.close()
        check_banner(response, ip, port)
    except ConnectionRefusedError:
        logging("{ip} tcp/{port} - closed".format(ip=ip,port=port))
    except socket.timeout:
        logging("{ip} tcp/{port} - no response".format(ip=ip,port=port))
    except BlockingIOError:
        logging("{ip} tcp/{port} - Resource temporarily unavailable".format(ip=ip,port=port))
    logging("Testing: {ip},tcp/{port} - released".format(ip=ip,port=port))

    



# ip_arg = "187.94.48.0/20"
ip_arg = "192.168.15.1/32"
ips_list = get_list_of_ips(ip_arg)

#https://kite.com/python/docs/threading.BoundedSemaphore
# pool = ThreadPool(processes=MAX_THREADS)
for ip in ips_list:
    #https://stackoverflow.com/a/56564152
    iterable = zip(repeat(ip), range(0, 65536),repeat(mysql_payload))
    with multiprocessing.Pool(processes=MAX_THREADS) as pool:
        all_links = pool.starmap(connect_host, iterable)


