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
import dpkt

class Layer:
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

class PktID(Layer):
  sName = "pid"

  def __init__(self, pid):
    self.c = dict()
    self.c['pid'] = str(pid).rjust(cfg.pktIDWidth, "0")

  def toPcap(self):
    return False

class TStamp(Layer):
  sName = "tstamp"
    
  def __init__(self, ts):
    self.c = dict()
    self.c['tstamp'] = "{:.2f}".format(ts)

  def toPcap(self):
    return float(self.c['tstamp'])

class Ethernet(Layer):
  sName = "ethernet"

  def __init__(self, data):
    self.c = dict()
    self.c['eth-dst'] = self.pcapToHexStr(data.dst, 2, ":")
    self.c['eth-src'] = self.pcapToHexStr(data.src, 2, ":")
    self.c['etype'] = self.intToHexStr(data.type).rjust(4, "0")

  # Returns dpkt Ethernet data structure 
  def toPcap(self):
    rv = dpkt.ethernet.Ethernet()
    rv.dst = self.hexStrToPcap(self.c['eth-dst'], ":")
    rv.src = self.hexStrToPcap(self.c['eth-src'], ":")
    rv.type = int(self.c['etype'], 16)
    return rv

class IPv4(Layer):
  sName = "ipv4"

  def __init__(self, data):
    self.c = dict()
    self.c['ipv4-dst'] = self.pcapToHexStr(data.dst, 2, ".")
    self.c['ipv4-src'] = self.pcapToHexStr(data.src, 2, ".")
    self.c['proto'] = self.intToHexStr(data.p).rjust(2, "0")
    self.c['off'] = data.off
    self.c['tos'] = data.tos
    self.c['sum'] = data.sum
    self.c['len'] = data.len
    self.c['id'] = data.id

  def toPcap(self):
    rv = dpkt.ip.IP()
    rv.dst = self.hexStrToPcap(self.c['ipv4-dst'], ".")
    rv.src = self.hexStrToPcap(self.c['ipv4-src'], ".")
    rv.p = int(self.c['proto'], 16)
    rv.off = self.c['off']
    rv.tos = self.c['tos']
    rv.sum = self.c['sum']
    rv.len = self.c['len']
    rv.id = self.c['id']
    return rv

class ICMP(Layer):
  sName = "icmp"
  
  def __init__(self, data):
    self.c = dict()
    self.c['type'] = self.intToHexStr(data.type)
    self.c['sum'] = self.intToHexStr(data.sum)
    self.c['id'] = self.intToHexStr(data.data.id)
    self.c['seq'] = self.intToHexStr(data.data.seq)
    self.c['data'] = self.pcapToHexStr(data.data.data, len(data.data.data), "?")

  # BROKEN:Need to further deal with data inside of other data
  def toPcap(self):
    rv = dpkt.icmp.ICMP()
    rv.type = int(self.c['type'], 16)
    rv.sum = int(self.c['sum'], 16)
    rv.id = int(self.c['id'], 16)
    rv.seq = int(self.c['seq'], 16)
    rv.data = self.hexStrToPcap(self.c['data'], "?")
    return rv

class TCP(Layer):
  sName = "tcp"

  def __init__(self, data):
    self.c = dict()
    self.c['dport'] = self.intToHexStr(data.dport)
    self.c['sport'] = self.intToHexStr(data.sport)
    self.c['win'] = self.intToHexStr(data.win)
    self.c['off_x2'] = data.off_x2
    self.c['sum'] = data.sum
    self.c['flags'] = data.flags
    self.c['data'] = data.data

    # http://www.python.org/dev/peps/pep-0237/
    self.c['seq'] = self.intToHexStr(data.seq).strip("L")
    self.c['ack'] = self.intToHexStr(data.ack).strip("L")

    # Parse TCP options
    self.opts = []
    self.opts = dpkt.tcp.parse_opts(data.opts)

  def toPcap(self):
    rv = dpkt.tcp.TCP()
    rv.dport = int(self.c['dport'], 16)
    rv.sport = int(self.c['sport'], 16)
    rv.seq = int(self.c['seq'], 16)
    rv.ack = int(self.c['ack'], 16)
    rv.win = int(self.c['win'], 16)
    rv.off_x2 = self.c['off_x2']
    rv.sum = self.c['sum']
    rv.flags = self.c['flags']
    rv.data = self.c['data']
    return rv

# Run through some tests for our Layers
# Takes a capture file
def test(cap):

  # PktID
  d = PktID(1)
  if(not d.toPcap()):
    print d.c['pid']
  
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
