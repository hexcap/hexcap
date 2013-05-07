#!/usr/bin/env python

'''
Copyright (C) 2013 Andrew McConachie

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
'''

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




