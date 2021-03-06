import sys
import os
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
from struct import pack


class DnsAnswer:
    def __init__(self, name: bytes, typ: int, cls: int, ttl: int, data_len: int, data: bytes):
        self.name = name
        self.type = typ
        self.cls = cls
        self.data_len = data_len
        self.data = data
        self.ttl = ttl


class DnsQuery:
    def __init__(self, name: bytes, typ: int, cls: int):
        self.name = name
        self.type = typ
        self.cls = cls

    def __hash__(self):
        return hash((self.name, self.type, self.cls))

    def __eq__(self, other):
        return self.name == other.name and self.cls == other.cls and self.type == other.type


class DnsMessage:
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    TXT = 16
    AAAA = 28
    OPT = 41

    codes = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
             28: "AAAA", 15: "MX", 16: "TXT", 41: "OPT"}

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
            question = DnsQuery(to_lower(q_name), q_type, q_class)
            self.questions.append(question)
            offset += 4

        self.answers_offset = offset
        self.authority_offset = self.parse_answers(
            offset, self.answers, self.answer_count)
        self.additional_offset = self.parse_answers(
            self.authority_offset, self.authority, self.authority_count)
        self.parse_answers(self.additional_offset,
                           self.additional, self.additional_count)

    def parse_a_data(self, a_len: int, a_type: int, data: bytes, offset: int):
        if a_type == DnsMessage.NS or a_type == DnsMessage.CNAME:
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
            a_type, a_class, a_ttl, a_data_len = unpack(
                "!HHIH", self.data[offset: offset + 10])
            a_data, offset = self.parse_a_data(
                a_data_len, a_type, self.data, offset + 10)
            if a_type == DnsMessage.NS:
                a_data = to_lower(a_data)
            answer = DnsAnswer(to_lower(a_name), a_type,
                               a_class, a_ttl, a_data_len, a_data)
            lst.append(answer)
        return offset

    @staticmethod
    def get_cant_fount_header_flags():
        return pack("!H", int("1000000000000011", 2))

    def __str__(self):
        res = ""
        res += 'Answer section:\n'
        for answer in self.answers:
            res += "{:20s} {:10s} {:5s} {:5s}   {}\n".format(answer.name.decode("ascii"), str(answer.ttl), "IN",
                                                          DnsMessage.codes[answer.type], answer.data)

        res += 'Authority section:\n'
        for answer in self.authority:
            res += "{:20s} {:10s} {:5s} {:5s}   {}\n".format(answer.name.decode("ascii"), str(answer.ttl), "IN",
                                                          DnsMessage.codes[answer.type], answer.data)

        res += 'Additional section:\n'
        for answer in self.additional:
            res += "{:20s}{:10s}{:5s}{:5s}   {}\n".format(answer.name.decode("ascii"), str(answer.ttl), "IN",
                                                          DnsMessage.codes[answer.type], answer.data)
        return res


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
        "202.12.27.33"
    ]

    def get_root_server(self):
        return self.root_dns_servers[self.root_dns_servers_id]

    def change_root_server(self):
        self.root_dns_servers_id = (
                                           self.root_dns_servers_id + 1) % len(self.root_dns_servers)

    def __init__(self):
        self.root_dns_servers_id = 0
        self.cache = {}
        self.zone_files = {}
        self.ip_cache = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def get_from_zone_file(self, message: DnsMessage):
        domain_name = message.questions[0].name.decode("ascii")
        if domain_name not in self.zone_files:
            return None
        z = self.zone_files[domain_name]
        tp = message.questions[0].type
        if z.root.records(DnsMessage.codes[tp]):
            answers = z.root.records(DnsMessage.codes[tp]).items
        else:
            answers = []
        res_data = pack("!HHHHHH", 0, 2 ** 15,
                        message.question_count, len(answers), 0, 0)
        res_data += message.data[message.questions_offset: message.answers_offset]
        for answer in answers:
            if tp == DnsMessage.MX:
                pr, tx = answer
                tx = get_labels_from_string(tx.encode("ascii"))
                res_data += pack("!HHHIHH", int("1100000000001100", 2), DnsMessage.MX, 1, z.names[domain_name].ttl,
                                 len(tx) + 2,
                                 pr) + tx
            elif tp == DnsMessage.TXT:
                tx = answer
                tx = tx.encode("ascii")
                res_data += pack("!HHHIHB", int("1100000000001100", 2), DnsMessage.TXT, 1, z.names[domain_name].ttl,
                                 len(tx) + 1,
                                 len(tx)) + tx
            elif tp == DnsMessage.NS:
                tx = answer
                tx = get_labels_from_string(tx.encode("ascii"))
                res_data += pack("!HHHIH", int("1100000000001100", 2), DnsMessage.NS, 1, z.names[domain_name].ttl,
                                 len(tx)) + tx
            elif tp == DnsMessage.A:
                tx = answer
                tx = tx.encode("ascii").split(b".")
                res_data += pack("!HHHIHBBBB", int("1100000000001100", 2), DnsMessage.A, 1, z.names[domain_name].ttl, 4,
                                 int(tx[0]),
                                 int(tx[1]), int(tx[2]), int(tx[3]))
            elif tp == DnsMessage.SOA:
                tx = answer.split(" ")
                data = get_labels_from_string(tx[0].encode(
                    "ascii")) + get_labels_from_string(tx[1].encode("ascii"))
                data += pack("!IIIII", int(tx[2]), int(tx[3]),
                             int(tx[4]), int(tx[5]), int(tx[6]))
                res_data += pack("!HHHIH", int("1100000000001100", 2), DnsMessage.SOA, 1, z.names[domain_name].ttl,
                                 len(data)) + data
        return DnsMessage(res_data)

    def cache_dns_response(self, response: DnsMessage):
        for cur_answer in response.answers:
            self.cache.setdefault((cur_answer.name, cur_answer.type), []).append(
                (cur_answer.ttl + time.time(), cur_answer.data))
        for cur_answer in response.authority:
            self.cache.setdefault((cur_answer.name, cur_answer.type), []).append(
                (cur_answer.ttl + time.time(), cur_answer.data))
        for cur_answer in response.additional:
            self.cache.setdefault((cur_answer.name, cur_answer.type), []).append(
                (cur_answer.ttl + time.time(), cur_answer.data))

    def get_list_by_key(self, key):
        res = []
        if key in self.cache:
            self.cache[key] = [domain_info for domain_info in self.cache[key] if
                               domain_info[0] >= time.time() + 1]
            if len(self.cache[key]) == 0:
                del self.cache[key]
            else:
                res = self.cache[key]

        return res

    def get_best_NS_servers(self, domain_name: bytes):
        my_list = domain_name.split(b".")
        my_list.reverse()
        res = []
        cur_sub_domain = b""
        for i in range(1, len(my_list)):
            cur_sub_domain = my_list[i] + b"." + cur_sub_domain
            lst = self.get_list_by_key((cur_sub_domain, DnsMessage.NS))
            if len(lst) > 0:
                res = lst
            else:
                break
        return res

    def get_cached_response(self, domain_name: bytes, tp: int):
        return self.get_list_by_key((domain_name, tp))

    def cache_ips(self, domain_name: bytes, response: DnsMessage):
        if domain_name not in self.ip_cache:
            self.ip_cache[domain_name] = []

        for cur_answer in response.answers:
            if cur_answer.type == DnsMessage.A:
                self.ip_cache[domain_name].append(
                    {"expiration_date": time.time() + cur_answer.ttl, "ip": ip_to_string(cur_answer.data)})

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

    def get_response(self, message: DnsMessage, ip_addr: str):

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(1)
        server_address = (str(ip_addr), 53)
        for _ in range(3):
            self.sock.sendto(message.data, server_address)
            try:
                data, addr = self.sock.recvfrom(constraints.max_data_size)
                response = DnsMessage(data)
                self.cache_dns_response(response)
                return response
            except OSError:
                continue
        if ip_addr in DnsRetriever.root_dns_servers:
            self.change_root_server()
            return self.get_response(message, self.get_root_server())
        return None


# This method is for store additional answers in dictionary
def get_additional_answers(response: DnsMessage):
    additional_records = {}
    for additional_answer in response.additional:
        if additional_answer.type == DnsMessage.A:
            additional_records[additional_answer.name] = ip_to_string(
                additional_answer.data)
    return additional_records


# This method returns authority servers by priority
def get_auth_servers_by_priority(response: DnsMessage, dns_retriever: DnsRetriever):
    with_ips = []
    without_ips = []
    for aut_server in response.authority:
        name = aut_server.data
        if aut_server.type != DnsMessage.NS:
            continue
        ips = dns_retriever.get_list_by_key((name, DnsMessage.A))
        if len(ips) > 0:
            with_ips.append(aut_server)
        else:
            without_ips.append(aut_server)
    return with_ips + without_ips


def get_response(message: DnsMessage, results: list):
    res_data = pack("!HHHHHH", 0, 2 ** 15,
                    message.question_count, len(results), 0, 0)
    res_data += message.data[message.questions_offset: message.answers_offset]
    for answer in results:
        res_data += pack("!HHHIH", int("1100000000001100", 2), message.questions[0].type, message.questions[0].cls,
                         int(answer[0] - time.time()),
                         len(answer[1])) + answer[1]
    return DnsMessage(res_data)


def get_ips_for_NS(dns_retriever: DnsRetriever, ns_list: list):
    lst = []
    for ns in ns_list:
        cur_ans = dns_retriever.get_list_by_key((ns, DnsMessage.A))
        for item in cur_ans:
            lst.append(ip_to_string(item[1]))
    return lst


def dns_recursion(dns_retriever: DnsRetriever, message: DnsMessage, ip_addrs: list, fixed: dict):
    if len(ip_addrs) == 0:
        return None
    for ip_addr in ip_addrs:
        if (ip_addr, message.questions[0]) in fixed:
            continue
        fixed[(ip_addr, message.questions[0])] = 1
        response = dns_retriever.get_response(message, ip_addr)
        print("Asking {:30} about {:30s} {:5s} {:7s}".format(ip_addr,
                                                           message.questions[0].name.decode(
                                                               "ascii"), "IN",
                                                           DnsMessage.codes[
                                                               message.questions[0].type]))
        print(response)
        if not response:
            continue
        if response.answer_count > 0:
            return response

        auth_servers = get_auth_servers_by_priority(
            response, dns_retriever)

        for aut_server in auth_servers:
            name = aut_server.data
            if aut_server.type != DnsMessage.NS:
                continue
            ips_with_ttl = dns_retriever.get_list_by_key((name, DnsMessage.A))
            ips_lst = []
            for ttl, ip in ips_with_ttl:
                ips_lst.append(ip_to_string(ip))
            if len(ips_lst) > 0:
                ans = dns_recursion(dns_retriever, message, ips_lst, fixed)
                if ans:
                    return ans
            else:
                data = copy.copy(message.data)
                lst = get_ips_for_NS(
                    dns_retriever, dns_retriever.get_best_NS_servers(name))
                lst.append(dns_retriever.get_root_server())
                data = data[: message.questions_offset] + get_labels_from_string(name) + data[
                                                                                         message.questions_name_end:]
                cur_response = dns_recursion(dns_retriever, DnsMessage(data), lst,
                                             fixed)
                lst_with_ttl = dns_retriever.get_list_by_key((name, DnsMessage.A))
                lst = []
                for item in lst_with_ttl:
                    lst.append(ip_to_string(item[1]))
                ans = dns_recursion(dns_retriever, message, lst, fixed)
                if ans:
                    return ans


def handle_client(sock: socket, addr: tuple, data: bytes, dns_retriever: DnsRetriever):
    message = DnsMessage(data)
    res_from_zone = dns_retriever.get_from_zone_file(message)
    if res_from_zone:
        response = res_from_zone
    else:
        cached_res = dns_retriever.get_cached_response(
            message.questions[0].name, message.questions[0].type)
        if len(cached_res) > 0:
            response = get_response(message, cached_res)
        else:
            lst = get_ips_for_NS(dns_retriever, dns_retriever.get_best_NS_servers(message.questions[0].name))
            lst.append(dns_retriever.get_root_server())
            response = dns_recursion(dns_retriever, message, lst, {})
    if response:
        sock.sendto(data[:2] + response.data[2:], addr)
    else:
        sock.sendto(
            data[:2] + DnsMessage.get_cant_fount_header_flags() + data[4:], addr)


def fill_from_config_files(config_path: str, dns_retriever: DnsRetriever):
    for filename in os.listdir(config_path):
        domain_name = filename[:-4]
        dns_retriever.zone_files[domain_name] = easyzone.zone_from_file(
            domain_name, config_path + "/" + filename)


def run_dns_server(config_path: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((constraints.listen_ip, constraints.listen_port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    dns_retriever = DnsRetriever()
    fill_from_config_files(config_path, dns_retriever)

    while True:
        data, addr = sock.recvfrom(constraints.max_data_size)
        handle_client(sock, addr, data, dns_retriever)
        # t = Thread(target=handle_client, args=(sock, addr, data, dns_retriever))
        # t.start()
        # t.join(3)
        # if t.is_alive():
        #     print("Can't find anything")
        #     t.join()


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
