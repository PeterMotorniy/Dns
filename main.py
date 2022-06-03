import pickle
import threading
import time
from collections import defaultdict

import dnslib
import socket

from data import DataHelper, Data, NSData, AData, AAAAData, PTRData

DNS_PORT = 53
HOST = "127.0.0.1"
DNS_SERVER = "8.8.8.8"
FINISHED = False
LOCK = threading.Lock()

cache = defaultdict(DataHelper)


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote_server_socket:
            server_sock.bind((HOST, DNS_PORT))
            remote_server_socket.connect((DNS_SERVER, DNS_PORT))
            server_sock.settimeout(1.0)
            remote_server_socket.settimeout(1.0)
            while not FINISHED:
                try:
                    query_data, customer_addr = server_sock.recvfrom(10000)
                    parser_query = dnslib.DNSRecord.parse(query_data)
                    with LOCK:
                        cache_records = cache.get(parser_query.q.qname.label)
                        if get_info_from_cache(cache_records, parser_query, server_sock, customer_addr):
                            continue
                        print('Turned to remote server')
                        get_info_from_server(customer_addr, query_data, remote_server_socket, server_sock)

                except socket.timeout:
                    pass
                except Exception as exc:
                    print(exc)


def get_info_from_server(customer_addr, query_data, remote_server_socket, server_sock):
    remote_server_socket.send(query_data)
    respond_data, _ = remote_server_socket.recvfrom(10000)
    server_sock.sendto(respond_data, customer_addr)
    parsed_respond = dnslib.DNSRecord.parse(respond_data)
    update_cache_records(parsed_respond)


def get_info_from_cache(cache_records, parser_query, server_sock, customer_addr):
    if cache_records is not None:
        cache_records.delete_expired_records()
        required_info = get_required_info(cache_records, parser_query)
        if required_info is not None:
            print('Information required from cache')
            add_answer_to_query(required_info, parser_query)
            server_sock.sendto(parser_query.pack(), customer_addr)
            return True
    return False


def add_answer_to_query(required_data, query):
    q_type = query.q.qtype
    q = query.q

    if q_type == dnslib.QTYPE.A:
        for addr in required_data.addresses:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.A(addr)
            ))
    if q_type == dnslib.QTYPE.AAAA:
        for addr in required_data.addresses:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.AAAA(addr)
            ))
    if q_type == dnslib.QTYPE.NS:
        for addr in required_data.servers:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.NS(addr)
            ))
    if q_type == dnslib.QTYPE.PTR:
        query.add_answer(dnslib.RR(
            rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
            rdata=dnslib.PTR(required_data.name))
        )


def get_required_info(cache_records, query) -> Data:
    type = query.q.qtype
    if type == dnslib.QTYPE.A:
        return cache_records.a
    elif type == dnslib.QTYPE.AAAA:
        return cache_records.aaaa
    elif type == dnslib.QTYPE.NS:
        return cache_records.ns
    elif type == dnslib.QTYPE.PTR:
        return cache_records.ptr


def get_cache_record(query):
    name = query.q.qname.label
    if name in cache:
        return cache[name]


def update_cache_records(dns_answer):
    for new_record in dns_answer.rr + dns_answer.ar:
        record_type = new_record.rtype
        name = new_record.rname.label
        cache_records = cache[name]
        if record_type == dnslib.QTYPE.NS:
            update_ns(new_record, cache_records)
        elif record_type == dnslib.QTYPE.A:
            update_a(new_record, cache_records)
        elif record_type == dnslib.QTYPE.AAAA:
            update_aaaa(new_record, cache_records)
        elif record_type == dnslib.QTYPE.PTR:
            update_ptr(new_record, cache_records)


def update_ns(new_record, cached_records):
    if cached_records.ns is None:
        cached_records.ns = NSData(new_record.ttl)
    cached_records.ns.servers.append(new_record.rdata.label.label)


def update_a(new_record, cached_records):
    if cached_records.a is None:
        cached_records.a = AData(new_record.ttl)
    cached_records.a.addresses.append(new_record.rdata.data)


def update_aaaa(new_record, cached_records):
    if cached_records.aaaa is None:
        cached_records.aaaa = AAAAData(new_record.ttl)
    cached_records.aaaa.addresses.append(new_record.rdata.data)


def update_ptr(new_record, cached_records):
    if cached_records.ptr is None:
        cached_records.ptr = PTRData(new_record.ttl, new_record.rdata.label.label)


def cache_clear_loop():
    while not FINISHED:
        time.sleep(10)
        with LOCK:
            expired_records_keys = []
            for key in cache:
                records = cache[key]
                records.delete_expired_records()
                if records.is_empty():
                    expired_records_keys.append(key)
            for key in expired_records_keys:
                cache.pop(key)


def input_handler_loop():
    global FINISHED
    while not FINISHED:
        inp = input()
        if inp == 'exit':
            FINISHED = True
            print('Wait until exit')
        elif inp == 'help':
            print('Enter "exit" to terminate')


if __name__ == '__main__':
    try:
        with open('cache', 'rb') as file:
            old_cache = pickle.loads(file.read())
            cache = old_cache
    except Exception:
        pass
    threading.Thread(target=cache_clear_loop).start()
    threading.Thread(target=input_handler_loop).start()
    try:
        start_server()
    except OSError as e:
        print(f'{HOST}/{DNS_PORT} busy')
    except socket.error as e:
        print(f'Can\'t connect to {DNS_SERVER}/{DNS_PORT}')

    try:
        with open('cache', 'wb') as file:
            file.write(pickle.dumps(cache))
    except Exception as e:
        print(e)
