import sys
import socket
from struct import unpack
from threading import Thread
import copy
from utils import to_lower
from utils import get_labels_from_string
from utils import ip_to_string
import constraints
import time
from easyzone import easyzone


class DnsMessage:
    A = 1
    NS = 2
    AAAA = 28
    OPT = 41

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
            q_name, offset = self.get_name(self.data, offset)
            self.questions_name_end = offset
            q_type, q_class = unpack("!HH", self.data[offset: offset + 4])
            question = {"qname": to_lower(q_name), "qtype": q_type, "qclass": q_class}
            self.questions.append(question)
            offset += 4

        self.answers_offset = offset
        self.authority_offset = self.parse_answers(offset, self.answers, self.answer_count)
        self.additional_offset = self.parse_answers(self.authority_offset, self.authority, self.authority_count)
        self.parse_answers(self.additional_offset, self.additional, self.additional_count)

    def parse_a_data(self, a_len: int, a_type: int, data: bytes, offset: int):
        if a_type == DnsMessage.NS:
            return self.get_name(data, offset)
        else:
            return data[offset: offset + a_len], offset + a_len

    def get_name(self, data: bytes, offset: int):
        a_name = bytearray()
        while True:
            label_len = unpack("!b", data[offset: offset + 1])[0]
            offset += 1
            if label_len == 0:
                break

            if (label_len >> 6 & 3) == 3:
                ptr = unpack("!H", data[offset - 1: offset + 1])[0]
                ptr = ptr & int('0011111111111111', 2)
                a_name += self.get_name(data, ptr)[0]
                offset += 1
                break
            else:
                a_name += data[offset: offset + label_len]
                offset += label_len
                a_name += b"."
        return bytes(a_name), offset

    def parse_answers(self, offset: int, lst: list, cnt: int):
        for _ in range(cnt):
            a_name, offset = self.get_name(self.data, offset)
            a_type, a_class, a_ttl, a_data_len = unpack("!HHIH", self.data[offset: offset + 10])
            a_data, offset = self.parse_a_data(a_data_len, a_type, self.data, offset + 10)
            if a_type == DnsMessage.NS:
                a_data = to_lower(a_data)
            answer = {"aname": to_lower(a_name), "atype": a_type, "aclass": a_class, "attl": a_ttl,
                      "adatalen": a_data_len, "adata": a_data}
            lst.append(answer)
        return offset


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
        self.cache = {}
        self.ip_cache = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def cache_dns_response(self, response: DnsMessage):
        ttl = 2 ** 60
        for cur_answer in response.answers:
            if cur_answer["atype"] in [DnsMessage.A, DnsMessage.AAAA, DnsMessage.NS]:
                ttl = min(ttl, cur_answer["attl"])
        for cur_answer in response.authority:
            if cur_answer["atype"] in [DnsMessage.A, DnsMessage.AAAA, DnsMessage.NS]:
                ttl = min(ttl, cur_answer["attl"])
        for cur_answer in response.additional:
            if cur_answer["atype"] in [DnsMessage.A, DnsMessage.AAAA, DnsMessage.NS]:
                ttl = min(ttl, cur_answer["attl"])
        key = (response.questions[0]["qname"], response.questions[0]["qclass"], response.questions[0]["qtype"])
        print(ttl)
        if key not in self.cache:
            print("new data")
            self.cache[key] = (ttl + time.time(), response)

    def get_cached_response(self, message: DnsMessage):
        key = (message.questions[0]["qname"], message.questions[0]["qclass"], message.questions[0]["qtype"])
        if key not in self.cache:
            return None
        if self.cache[key][0] < time.time():
            del self.cache[key]
        if key not in self.cache:
            return None
        else:
            return self.cache[key][1]

    def cache_ips(self, domain_name: bytes, response: DnsMessage):
        if domain_name not in self.ip_cache:
            self.ip_cache[domain_name] = []

        for cur_answer in response.answers:
            if cur_answer["atype"] == DnsMessage.A:
                self.ip_cache[domain_name].append(
                    {"expiration_date": time.time() + cur_answer["attl"], "ip": ip_to_string(cur_answer["adata"])})

    def get_cached_ips(self, domain_name: bytes):
        if domain_name not in self.ip_cache:
            return []
        self.ip_cache[domain_name] = [ip_info for ip_info in self.ip_cache[domain_name] if
                                      ip_info["expiration_date"] >= time.time()]

        if len(self.ip_cache[domain_name]) == 0:
            del self.ip_cache[domain_name]
            return []
        else:
            return [ip_info["ip"] for ip_info in self.ip_cache[domain_name]]

    def get_response(self, message: DnsMessage, ip_addr=root_dns_servers[0]):
        cached_response = self.get_cached_response(message)
        if cached_response:
            return cached_response

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(1)
        server_address = (str(ip_addr), 53)

        for _ in range(3):
            self.sock.sendto(message.data, server_address)
            try:
                data, addr = self.sock.recvfrom(constraints.max_data_size)
                response = DnsMessage(data)
                return response
            except OSError:
                continue

        return None


def dns_recursion(dns_retriever: DnsRetriever, message: DnsMessage, ip_addrs: list):
    if len(ip_addrs) == 0:
        return None
    for ip_addr in ip_addrs:
        response = dns_retriever.get_response(message, ip_addr)
        if not response:
            continue
        if response.answer_count > 0:
            dns_retriever.cache_dns_response(response)
            return response
        additional_records = {}
        for additional_answer in response.additional:
            if additional_answer["atype"] == DnsMessage.A:
                additional_records[additional_answer["aname"]] = ip_to_string(additional_answer["adata"])

        for aut_server in response.authority:
            name = aut_server["adata"]
            if aut_server["atype"] != DnsMessage.NS:
                continue
            if name in additional_records:
                ans = dns_recursion(dns_retriever, message, [additional_records[name]])
                if ans:
                    dns_retriever.cache_dns_response(ans)
                    return ans
            else:
                data = copy.copy(message.data)
                lst = dns_retriever.get_cached_ips(name)
                if len(lst) == 0:
                    data = data[: message.questions_offset] + get_labels_from_string(name) + data[
                                                                                             message.questions_name_end:]
                    cur_response = dns_recursion(dns_retriever, DnsMessage(data), DnsRetriever.root_dns_servers)
                    if cur_response:
                        dns_retriever.cache_ips(name, cur_response)
                lst = dns_retriever.get_cached_ips(name)
                ans = dns_recursion(dns_retriever, message, lst)
                if ans:
                    dns_retriever.cache_dns_response(ans)
                    return ans


def handle_client(sock: socket, addr: tuple, data: bytes, dns_retriever: DnsRetriever):
    message = DnsMessage(data)
    response = dns_recursion(dns_retriever, message, DnsRetriever.root_dns_servers)
    if response:
        sock.sendto(data[:2] + response.data[2:], addr)
    else:
        sock.sendto(data, addr)


def run_dns_server(config_path: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((constraints.listen_ip, constraints.listen_port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_retriever = DnsRetriever()
    while True:
        data, addr = sock.recvfrom(constraints.max_data_size)
        t = Thread(target=handle_client, args=(sock, addr, data, dns_retriever))
        t.start()
        t.join(3)
        if t.is_alive():
            print("Can't find anything")
            t.join()


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
