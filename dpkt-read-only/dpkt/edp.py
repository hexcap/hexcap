"""Extreme Discovery Protocol."""

import dpkt
import sys
sys.path.insert(0, '/home/smutt/hacking/python/hexcap/')
import cfg

class EDP(dpkt.Packet):
    __hdr__ = (
        ('v', 'B', 1),
        ('res', 'B', 0),
        ('len', 'H', 0),
        ('sum', 'H', 0),
        ('seq', 'H', 0),
        ('mid', 'H', 0),
        ('mac', '6s', '')
        )
    
    def __str__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__str__(self))
        return dpkt.Packet.__str__(self)
