import sys
import os
import socket
from struct import unpack
from threading import Thread

Max_data_size = 4096


class DnsRetriever:
    root_dns_servers = [
        "198.41.0.4",
        "192.228.79.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "128.63.2.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33"]

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 0))

    def get_response(self, data):
        self.sock.sendto(data, (self.root_dns_servers[0], 53))
        data, addr = self.sock.recvfrom(Max_data_size)
        message = DnsMessage(data)
        print(addr)


class DnsMessage:

    def __init__(self, data):
        lst = unpack("!HHHHHH", data[:12])
        self.isResponse = lst[1] & int('1000000000000000', 2) >> 15
        self.recursion = lst[1] & int('0000001000000000', 2) >> 9
        self.id = lst[0]
        self.question_count = lst[2]
        self.answer_count = lst[3]
        self.authority_count = lst[4]
        self.additional_count = lst[5]
        self.questions = []
        self.answers = []
        self.authority = []
        self.additional = []
        self.data = data
        self.questions_offset = 12
        offset = 12
        for _ in range(self.question_count):
            q_name = bytearray()
            while True:
                label_len = unpack("!b", data[offset: offset + 1])[0]
                offset += 1
                if label_len == 0:
                    break

                if (label_len >> 6 & 3) == 3:
                    ptr = unpack("!H", data[offset - 1: offset + 1])[0]
                    ptr = ptr & int('0011111111111111', 2)
                    q_name += self.get_txt_from_offset(ptr)
                    q_name += b"."
                    offset += 1
                    break
                else:
                    q_name += self.data[offset: offset + label_len]
                    offset += label_len
                    q_name += b"."

            q_type, q_class = unpack("!HH", data[offset: offset + 4])
            question = {"qname": q_name, "qtype": q_type, "qclass": q_class}
            self.questions.append(question)
            offset += 4

        self.answers_offset = offset
        self.authority_offset = self.parse_answers(offset, self.answers, self.answer_count)
        self.additional_offset = self.parse_answers(offset, self.authority, self.authority_count)
        self.parse_answers(offset, self.additional, self.additional_count)

        print(self.questions)
        print(self.answers)
        print(self.authority)
        print(self.additional)

    def get_txt_from_offset(self, offset):
        label_len = unpack("!b", self.data[offset: offset + 1])[0]
        if (label_len >> 6 & 3) == 3:
            ptr = label_len & int('00111111', 2)
            return self.get_txt_from_offset(ptr)
        else:
            return self.data[offset: offset + label_len + 1]

    def parse_answers(self, offset, lst, cnt):
        for _ in range(cnt):
            a_name = bytearray()
            while True:
                label_len = unpack("!b", self.data[offset: offset + 1])[0]
                offset += 1
                if label_len == 0:
                    offset += 1
                    break

                if (label_len >> 6 & 3) == 3:
                    ptr = unpack("!H", self.data[offset - 1: offset + 1])[0]
                    ptr = ptr & int('0011111111111111', 2)
                    a_name += self.get_txt_from_offset(ptr)
                    a_name += b"."
                    offset += 1
                    break
                else:
                    a_name += self.data[offset: offset + label_len]
                    offset += label_len
                    a_name += b"."

            a_type, a_class, a_ttl, a_data_len = unpack("!HHIH", self.data[offset: offset + 10])
            a_data = self.data[offset + 10: offset + 10 + a_data_len]
            answer = {"aname": a_name, "atype": a_type, "aclass": a_class, "attl": a_ttl,
                      "adatalen": a_data_len, "adata": a_data}
            lst.append(answer)
            offset += 10 + a_data_len
        return offset


def parse_dns_message(data: bytes):
    lst = unpack("!HHHHHH", data[:12])
    isResponse = lst[1] & int('1000000000000000', 2) >> 15
    opCode = lst[1] & int('0111100000000000', 2) >> 11
    truncated = lst[1] & int('0000010000000000', 2) >> 10
    recursion = lst[1] & int('0000001000000000', 2) >> 9
    res = {"ID": lst[0],
           "isResponse": isResponse,
           "truncated": truncated,
           "opCode": opCode,
           "recursion": recursion,
           "questions": lst[2],
           "answers": lst[3],
           "authority": lst[4],
           "additional": lst[5]}
    return res


def handle_client(sock: socket, addr, data: bytes, dns_retriever: DnsRetriever):
    print(data)
    print(addr)
    message = DnsMessage(data)
    if message.isResponse != 0:
        return
    dns_retriever.get_response(data)


def run_dns_server(configpath):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 8080))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_retriever = DnsRetriever()
    print(configpath)

    while True:
        data, addr = sock.recvfrom(Max_data_size)
        Thread(target=handle_client, args=(sock, addr, data, dns_retriever)).start()


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
