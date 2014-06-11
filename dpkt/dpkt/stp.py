# $Id: stp.py 23 2006-11-08 15:45:33Z dugsong $

"""Spanning Tree Protocol."""

import dpkt

class STP(dpkt.Packet):
    __hdr__ = (
        ('proto_id', 'H', 0),
        ('v', 'B', 0),
        ('type', 'B', 0),
        ('flags', 'B', 0),
        ('root_id', '8s', ''),
        ('root_path', 'I', 0),
        ('bridge_id', '8s', ''),
        ('port_id', 'H', 0),
        ('age_x2', 'H', 0),
        ('max_age_x2', 'H', 0),
        ('hello_x2', 'H', 0),
        ('fd_x2', 'H', 0)
        )

    def _get_age(self): return self.age_x2 >> 8
    def _set_age(self, age): self.age_x2 = age << 8
    age = property(_get_age, _set_age)

    def _get_max_age(self): return self.max_age_x2 >> 8
    def _set_max_age(self, max_age): self.max_age_x2 = max_age << 8
    max_age = property(_get_max_age, _set_max_age)

    def _get_hello(self): return self.hello_x2 >> 8
    def _set_hello(self, hello): self.hello_x2 = hello << 8
    hello = property(_get_hello, _set_hello)

    def _get_fd(self): return self.fd_x2 >> 8
    def _set_fd(self, fd): self.fd_x2 = fd << 8
    fd = property(_get_fd, _set_fd)

    
