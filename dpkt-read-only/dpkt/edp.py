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
        ('seq', 'H', ''),
        ('mid', 'H', 0),
        ('mac', '6s', '')
        )


    
