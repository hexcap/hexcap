#!/usr/bin/env python

import sys
import dpkt
import time
from inspect import getmembers
from pprint import pprint
from collections import OrderedDict

print "now:" + str(time.time())
pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
for ts, pkt in pcIn:
  p = dpkt.ethernet.Ethernet(pkt)
  print str(hex(p.type))

#  turd = "{:.2f}".format(ts)
#  print str(float(turd))




