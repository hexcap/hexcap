#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt

reader = dpkt.pcap.Reader(open(sys.argv[1]))
print str(reader.datalink())
