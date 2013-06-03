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

import cfg
import sys
sys.path.insert(0, '/home/smutt/hacking/python/hexcap/dpkt-read-only/')
import dpkt
from collections import OrderedDict

class Layer:
  RO = False # Is this layer read-only?

  # Convert int to hex without leading 0x
  def intToHexStr(self, num):
    x,rv = hex(num).split("0x")
    return rv

  # Change pcap character data to padded hex string without leading 0x
  def binToHexStr(self, val, ln):
    x,rv = hex(ord(val)).split("0x")
    return rv.rjust(ln, "0")

  # Change dpkt character bytes to string hex values of length ln with a delimiter of delim
  # ln corresponds to how many nibbles you want between each delim
  def pcapToHexStr(self, bytes, ln, delim):
    rv = ""
    for b in bytes:
      rv += self.binToHexStr(b, ln) + delim
    return rv.rstrip(delim)

  # Change string hex values to dpkt character bytes ignoring delimiter of delim
  def hexStrToPcap(self, s, delim):
    rv = ""
    bytes = s.split(delim)
    for b in bytes:
      rv += chr(int(b, 16))
    return rv

  # Sets column to val
  def setColumn(self, col, val):
    self.vals[col] = val

  # For debugging only
  def dump(self):
    return repr(self.vals)

class PktID(Layer):
  ID = "pid"
  RO = True

  cols = OrderedDict() # OrderedDict of columns
  cols['pid'] = cfg.pktIDWidth

  def __init__(self, pid):
    self.vals = dict()
    self.vals['pid'] = str(pid).rjust(cfg.pktIDWidth, "0")

  # Overloading virtual since we're picky about pid
  def setColumn(self, col, val):
    # Fill PID with ?'s if we get passed -1
    if(val == -1):
      self.vals[col] = ''
      for ii in xrange(0, cfg.pktIDWidth):
        self.vals[col] += "?"
    else:
      self.vals[col] = str(val).rjust(cfg.pktIDWidth, "0")

  def toPcap(self):
    return False

class TStamp(Layer):
  ID = "tstamp"
  RO = True

  cols = OrderedDict() # OrderedDict of columns
  cols['tstamp'] = 13
    
  def __init__(self, ts):
    self.vals = dict()
    self.vals['tstamp'] = "{:.2f}".format(ts)

  def toPcap(self):
    return float(self.vals['tstamp'])

class Ethernet(Layer):
  ID = "ethernet"

  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17
  cols['etype'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['eth-dst'] = self.pcapToHexStr(data.dst, 2, ":")
    self.vals['eth-src'] = self.pcapToHexStr(data.src, 2, ":")
    self.vals['etype'] = self.intToHexStr(data.type).rjust(4, "0")

  # Returns dpkt Ethernet data structure 
  def toPcap(self):
    rv = dpkt.ethernet.Ethernet()
    rv.dst = self.hexStrToPcap(self.vals['eth-dst'], ":")
    rv.src = self.hexStrToPcap(self.vals['eth-src'], ":")
    rv.type = int(self.vals['etype'], 16)
    return rv

# Assumptions
# HTYPE == 1(Ethernet)
# PTYPE == 0x0800(IPv4)
class ARP(Layer):
  ID = "iparp"

  cols = OrderedDict()
  cols['oper'] = 4 # Operation
  cols['sha'] = 17 # Sender MAC
  cols['tha'] = 17 # Target MAC
  cols['spa'] = 11 # Sender IP
  cols['tpa'] = 11 # Target IP
  
  def __init__(self, data):
    self.vals = dict()
    self.vals['oper'] = self.intToHexStr(data.op).rjust(4, "0")
    self.vals['sha'] = self.pcapToHexStr(data.sha, 2, ":")
    self.vals['tha'] = self.pcapToHexStr(data.tha, 2, ":")
    self.vals['spa'] = self.pcapToHexStr(data.spa, 2, ".")
    self.vals['tpa'] = self.pcapToHexStr(data.tpa, 2, ".")

  def toPcap(self):
    rv = dpkt.arp.ARP()
    rv.op = int(self.vals['oper'], 16)
    rv.sha = self.hexStrToPcap(self.vals['sha'], ":")
    rv.tha = self.hexStrToPcap(self.vals['tha'], ":")
    rv.spa = self.hexStrToPcap(self.vals['spa'], ".")
    rv.tpa = self.hexStrToPcap(self.vals['tpa'], ".")
    return rv

class IPv4(Layer):
  ID = "ipv4"

  cols = OrderedDict() # OrderedDict of columns
  cols['ipv4-dst'] = 11
  cols['ipv4-src'] = 11
  cols['proto'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['ipv4-dst'] = self.pcapToHexStr(data.dst, 2, ".")
    self.vals['ipv4-src'] = self.pcapToHexStr(data.src, 2, ".")
    self.vals['proto'] = self.intToHexStr(data.p).rjust(2, "0")
    self.vals['off'] = data.off
    self.vals['tos'] = data.tos
    self.vals['sum'] = data.sum
    self.vals['len'] = data.len
    self.vals['id'] = data.id

  def toPcap(self):
    rv = dpkt.ip.IP()
    rv.dst = self.hexStrToPcap(self.vals['ipv4-dst'], ".")
    rv.src = self.hexStrToPcap(self.vals['ipv4-src'], ".")
    rv.p = int(self.vals['proto'], 16)
    rv.off = self.vals['off']
    rv.tos = self.vals['tos']
    rv.sum = self.vals['sum']
    rv.len = self.vals['len']
    rv.id = self.vals['id']
    return rv

# Assumes ICMP type is either 0 or 8(echo or echo_reply)
class ICMP(Layer):
  ID = "icmp"

  cols = OrderedDict() # OrderedDict of columns
  cols['type'] = 4
  cols['sum'] = 4
  cols['id'] = 4
  cols['seq'] = 3

  def __init__(self, data):
    self.vals = dict()
    self.vals['type'] = self.intToHexStr(data.type)
    self.vals['sum'] = self.intToHexStr(data.sum)
    self.vals['id'] = self.intToHexStr(data.data.id)
    self.vals['seq'] = self.intToHexStr(data.data.seq)
    self.vals['data'] = data.data.data

  def toPcap(self):
    rv = dpkt.icmp.ICMP()
    rv.data = dpkt.icmp.ICMP.Echo()
    rv.type = int(self.vals['type'], 16)
    rv.sum = int(self.vals['sum'], 16)
    rv.data.id = int(self.vals['id'], 16)
    rv.data.seq = int(self.vals['seq'], 16)
    rv.data.data = self.vals['data']
    return rv

class TCP(Layer):
  ID = "tcp"

  cols = OrderedDict() # OrderedDict of columns
  cols['dport'] = 5
  cols['sport'] = 5
  cols['seq'] = 8
  cols['ack'] = 8
  cols['win'] = 4

  def __init__(self, data):
    self.vals = dict()
    self.vals['dport'] = self.intToHexStr(data.dport)
    self.vals['sport'] = self.intToHexStr(data.sport)
    self.vals['win'] = self.intToHexStr(data.win)
    self.vals['sum'] = data.sum
    self.vals['flags'] = data.flags
    self.vals['data'] = data.data

    # http://www.python.org/dev/peps/pep-0237/
    self.vals['seq'] = self.intToHexStr(data.seq).strip("L")
    self.vals['ack'] = self.intToHexStr(data.ack).strip("L")
    self.vals['off'] = data.off

    # Parse TCP options
    self.vals['opts'] = data.opts
    #    self.opts = []
    #    self.opts = dpkt.tcp.parse_opts(data.opts)
    #    cfg.dbg(repr(self.opts))

  def toPcap(self):
    rv = dpkt.tcp.TCP()
    rv.dport = int(self.vals['dport'], 16)
    rv.sport = int(self.vals['sport'], 16)
    rv.seq = int(self.vals['seq'], 16)
    rv.ack = int(self.vals['ack'], 16)
    rv.win = int(self.vals['win'], 16)
    rv.sum = self.vals['sum']
    rv.flags = self.vals['flags']
    rv.opts = self.vals['opts']
    rv.data = self.vals['data']
    rv.off = self.vals['off']
    return rv

# Run through some tests for our Layers
# Takes a capture file
def test(cap):

  # PktID
  d = PktID(1)
  if(not d.toPcap()):
    print d.vals['pid']
  
  # TStamp
  d = TStamp(1986187623.12)
  print repr(d.toPcap())

  # Ethernet
  l = []
  f = open(cap, 'rb')
  pcIn = dpkt.pcap.Reader(f)
  for ts, pkt in pcIn:
    l.append(Ethernet(dpkt.ethernet.Ethernet(pkt)))
  f.close()

  for eth in l:
    print "Ethernet:" + repr(eth.toPcap())

  # IPv4
  l = []
  f = open(cap, 'rb')
  pcIn = dpkt.pcap.Reader(f)
  for ts, pkt in pcIn:
    p = dpkt.ethernet.Ethernet(pkt)
    if("0x800" == hex(p.type)):
      l.append(IPv4(p.data))
  f.close()

  if(len(l) > 0):
    for ip in l:
      print "IPv4:" + repr(ip.toPcap())

  # ICMP
  l = []
  f = open(cap, 'rb')
  pcIn = dpkt.pcap.Reader(f)
  for ts, pkt in pcIn:
    p = dpkt.ethernet.Ethernet(pkt)
    if("0x800" == hex(p.type)):
      if(p.data.p == 1):
        l.append(ICMP(p.data.data))
  f.close()

  if(len(l) > 0):
    for icmp in l:
      print "ICMP:" + repr(icmp.toPcap())

  # TCP
  l = []
  f = open(cap, 'rb')
  pcIn = dpkt.pcap.Reader(f)
  for ts, pkt in pcIn:
    p = dpkt.ethernet.Ethernet(pkt)
    if("0x800" == hex(p.type)):
      if(p.data.p == 6):
        l.append(TCP(p.data.data))
  f.close()

  if(len(l) > 0):
    for tcp in l:
      print "TCP:" + repr(tcp.toPcap())

#test('t.pcap')
