import time
from typing import Optional


class Data:
    def __init__(self, ttl):
        self._init_time = time.time()
        self.ttl = ttl

    def is_expired(self):
        return self.remain_ttl() == 0

    def remain_ttl(self):
        passed_time = int(time.time() - self._init_time)
        return max(0, self.ttl - passed_time)


class DataHelper:
    def __init__(self):
        self.a: Optional[AData] = None
        self.aaaa: Optional[AAAAData] = None
        self.ns: Optional[NSData] = None
        self.ptr: Optional[PTRData] = None

    def delete_expired_records(self):
        if self.ns is not None and self.ns.is_expired():
            self.ns = None
        if self.ptr is not None and self.ptr.is_expired():
            self.ptr = None
        if self.a is not None and self.a.is_expired():
            self.a = None
        if self.aaaa is not None and self.aaaa.is_expired():
            self.aaaa = None

    def is_empty(self):
        return not any([self.a, self.aaaa, self.ptr, self.ns])


class AAAAData(Data):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.addresses = []


class AData(Data):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.addresses = []


class NSData(Data):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.servers = []


class PTRData(Data):
    def __init__(self, ttl, name):
        super().__init__(ttl)
        self.name = name
