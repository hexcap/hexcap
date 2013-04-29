#!/usr/bin/env python

import sys
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
    print repr(dpkt.ethernet.Ethernet(pkt)) + " " + str(ts)



