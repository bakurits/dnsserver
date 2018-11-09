import sys
import os
import socket
from struct import unpack
from struct import pack
from threading import Thread
import copy

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
        self.sock.settimeout(2)

    def get_response(self, data: bytes, ip_addr=root_dns_servers[0]):
        random_bits = os.urandom(2)

        data = random_bits + data[2:]
        server_address = (str(ip_addr), 53)
        self.sock.sendto(data, server_address)

        while True:
            try:
                data, addr = self.sock.recvfrom(Max_data_size)
                if data[:2] == random_bits:
                    return DnsMessage(data)
            except OSError:
                return None


class DnsMessage:

    def __init__(self, data: bytes):
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
        self.data = copy.copy(data)
        self.questions_offset = 12
        offset = 12
        for _ in range(self.question_count):
            q_name = bytearray()
            while True:
                label_len = unpack("!b", self.data[offset: offset + 1])[0]
                offset += 1
                if label_len == 0:
                    break

                if (label_len >> 6 & 3) == 3:
                    ptr = unpack("!H", self.data[offset - 1: offset + 1])[0]
                    ptr = ptr & int('0011111111111111', 2)
                    q_name += self.get_txt_from_offset(ptr)
                    q_name += b"."
                    offset += 1
                    break
                else:
                    q_name += self.data[offset: offset + label_len]
                    offset += label_len
                    q_name += b"."
            self.questions_name_end = offset
            q_type, q_class = unpack("!HH", self.data[offset: offset + 4])
            question = {"qname": bytes(q_name), "qtype": q_type, "qclass": q_class}
            self.questions.append(question)
            offset += 4

        self.answers_offset = offset
        self.authority_offset = self.parse_answers(offset, self.answers, self.answer_count)
        self.additional_offset = self.parse_answers(offset, self.authority, self.authority_count)
        self.parse_answers(offset, self.additional, self.additional_count)

    def get_txt_from_offset(self, offset: int):
        label_len = unpack("!b", self.data[offset: offset + 1])[0]
        if (label_len >> 6 & 3) == 3:
            ptr = label_len & int('00111111', 2)
            return self.get_txt_from_offset(ptr)
        else:
            return self.data[offset: offset + label_len + 1]

    def parse_answers(self, offset: int, lst: list, cnt: int):
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
            answer = {"aname": bytes(a_name), "atype": a_type, "aclass": a_class, "attl": a_ttl,
                      "adatalen": a_data_len, "adata": a_data}
            lst.append(answer)
            offset += 10 + a_data_len
        return offset


def ip_to_string(data: bytes):
    res = ""
    for octet in data:
        res += str(octet) + "."
    return res[: -1]


def dns_recursion(dns_retriever: DnsRetriever, message: DnsMessage, ip_addrs: list):
    if len(ip_addrs) == 0:
        return None
    for ip_addr in ip_addrs:
        response = dns_retriever.get_response(message.data, ip_addr)
        if not response:
            continue
        if response.answer_count > 0:
            return response
        checked_resources = []
        for additional_answer in response.additional:
            checked_resources.append(additional_answer["aname"])
            if additional_answer["atype"] == 1:
                print(additional_answer)
                ans = dns_recursion(dns_retriever, message, [ip_to_string(additional_answer["adata"])])
                if ans:
                    return ans

        for aut_server in response.authority:
            if not aut_server["aname"] in checked_resources:
                labels = aut_server["aname"].split(b".")
                new_name = bytearray()
                for label in labels:
                    new_name += pack("!Hs", len(label), label)
                new_name += 0
                data = copy.copy(message.data)
                data = data[: message.questions_offset] + new_name + data[message.questions_name_end]
                cur_response = dns_recursion(dns_retriever, DnsMessage(data), DnsRetriever.root_dns_servers)
                if cur_response:
                    lst = []
                    for cur_answer in cur_response.answers:
                        if cur_answer["atype"] == 1:
                            lst.append(ip_to_string(cur_answer["adata"]))
                    ans = dns_recursion(dns_retriever, message, lst)
                    if ans:
                        return ans

def handle_client(sock: socket, addr: tuple, data: bytes, dns_retriever: DnsRetriever):
    message = DnsMessage(data)
    response = dns_recursion(dns_retriever, message, DnsRetriever.root_dns_servers)
    answer = message.data[:2] + response.data[2:]
    sock.sendto(answer, addr)


def run_dns_server(config_path: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 8080))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_retriever = DnsRetriever()
    print(config_path)

    while True:
        data, addr = sock.recvfrom(Max_data_size)
        t = Thread(target=handle_client, args=(sock, addr, data, dns_retriever))
        t.start()
        t.join(10)
        if t.is_alive():
            print("can't get answer")


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
