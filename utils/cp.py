#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import sys
#sys.path.insert(0, sys.path[0] + '/../dpkt')
sys.path.insert(0, '/home/smutt/hacking/dpkt')
import dpkt
from inspect import getmembers
from pprint import pprint

if(len(sys.argv) > 2):
  pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
  pcOut = dpkt.pcap.Writer(open(sys.argv[2], 'wb'))
  for ts, pkt in pcIn:
    p = dpkt.ethernet.Ethernet(pkt)
    pcOut.writepkt(dpkt.ethernet.Ethernet.pack(p), ts)
  pcOut.close()

else:
  pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
  for ts, pkt in pcIn:
    p = dpkt.ethernet.Ethernet(pkt)
    print repr(p)
