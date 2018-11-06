import sys
import os
import socket
from struct import unpack
from threading import Thread


def parse_DNS_message(data: bytes):
    lst = unpack("!HHHHHH", data[:12])
    isResponse = lst[1] & int('1000000000000000', 2) >> 15
    opCode = lst[1] & int('0111100000000000', 2) >> 11
    truncated = lst[1] & int('0000010000000000', 2) >> 10
    recursion = lst[1] & int('0000001000000000', 2) >> 9
    res = {"ID": lst[0],
           "isResponse" : isResponse,
           "truncated": truncated,
           "opCode" : opCode,
           "recursion" : recursion,
           "questions": lst[2],
           "answers": lst[3],
           "authority": lst[4],
           "additional": lst[5]}
    return res

def handle_client(sock: socket, addr, data: bytes):
    print(data)
    print(addr)
    message = parse_DNS_message(data)
    if message["isResponse"] != 0 :
        return
    sock.sendto(data, addr)



def run_dns_server(configpath):
    lst = unpack('hll', b'bakuribakuribakuribakuri')
    print(str(lst))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 8080))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print(configpath)

    while True:
        data, addr = sock.recvfrom(512)
        Thread(target=handle_client, args=(sock, addr, data)).start()


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
