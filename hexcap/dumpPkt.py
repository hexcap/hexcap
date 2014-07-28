#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import sys
sys.path.insert(0, '../dpkt/')
import dpkt

pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
ii = 0
for ts, pkt in pcIn:
  ii += 1
  print "Pkt:" + str(ii) + " ts:" + str(ts)

  s = ''
  for c in pkt:
    s += hex(ord(c)) + "|"
  print s.rstrip("|")
