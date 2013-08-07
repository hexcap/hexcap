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
sys.path.insert(0, '../dpkt-read-only/')
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
    if(hasattr(p, 'tag')):
      print "\n"
      print "dot1q:" + hex(p.tag)
      print "dot1p:" + hex(p.dot1p)
      print "etype:" + hex(p.type)
    print repr(p)
