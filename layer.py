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

# For now we just let dpkt do all the checksum calculations
# So it's not possible to create packets with invalid checksums
# AND any packets opened with invalid checksums will have them corrected at save time

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
  position = 0

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
  position = 1

  cols = OrderedDict() # OrderedDict of columns
  cols['tstamp'] = 13
    
  def __init__(self, ts):
    self.vals = dict()
    self.vals['tstamp'] = "{:.2f}".format(ts)

  def toPcap(self):
    return float(self.vals['tstamp'])

class Ethernet(Layer):
  ID = "ethernet"
  position = 10


  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17
  cols['etype'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['eth-dst'] = self.pcapToHexStr(data.dst, 2, ":")
    self.vals['eth-src'] = self.pcapToHexStr(data.src, 2, ":")
    self.vals['etype'] = self.intToHexStr(data.type).rjust(4, "0")

  def toPcap(self):
    rv = dpkt.ethernet.Ethernet()
    rv.dst = self.hexStrToPcap(self.vals['eth-dst'], ":")
    rv.src = self.hexStrToPcap(self.vals['eth-src'], ":")
    rv.type = int(self.vals['etype'], 16)

    return rv

# Writing does not yet work(needs work in dpkt ethernet.py)
class Dot1q(Layer):
  ID = "802.1q"
  position = 20

  cols = OrderedDict() # OrderedDict of columns
  cols['tag'] = 5
  cols['dot1p'] = 5
  cols['etype'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['tag'] = self.intToHexStr(data.tag).rjust(4, "0")
    self.vals['dot1p'] = self.intToHexStr(data.pcp).rjust(4, "0")
    self.vals['etype'] = self.intToHexStr(data.type).rjust(4, "0")

  def toPcap(self):
    return False

class STP(Layer):
  ID = "stp"
  position = 30

  cols = OrderedDict() # OrderedDict of columns
  cols['root-id'] = 23
  cols['bridge-id'] = 23
  cols['port-id'] = 7
  cols['age'] = 5
  cols['max-age'] = 7
  cols['hello'] = 5
  cols['fwd-delay'] = 9
  cols['cost'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['root-id'] = self.pcapToHexStr(data.root_id, 2, ":")
    self.vals['bridge-id'] = self.pcapToHexStr(data.bridge_id, 2, ":")
    self.vals['port-id'] = self.intToHexStr(data.port_id).rjust(4, "0")
    self.vals['age'] = self.intToHexStr(data.age).rjust(2, "0")
    self.vals['max-age'] = self.intToHexStr(data.max_age).rjust(2, "0")
    self.vals['hello'] = self.intToHexStr(data.hello).rjust(2, "0")
    self.vals['fwd-delay'] = self.intToHexStr(data.fd).rjust(2, "0")
    self.vals['cost'] = self.intToHexStr(data.root_path).rjust(2, "0")
    self.vals['data'] = data.data

  def toPcap(self):
    rv = dpkt.stp.STP()
    rv.root_id = self.hexStrToPcap(self.vals['root-id'], ":")
    rv.bridge_id = self.hexStrToPcap(self.vals['bridge-id'], ":")
    rv.port_id = int(self.vals['port-id'], 16)
    rv.age = int(self.vals['age'], 16)
    rv.max_age = int(self.vals['max-age'], 16)
    rv.hello = int(self.vals['hello'], 16)
    rv.fd = int(self.vals['fwd-delay'], 16)
    rv.path = int(self.vals['cost'], 16)
    rv.data = self.vals['data']
    return rv

# Assumptions
# HTYPE == 1(Ethernet)
# PTYPE == 0x0800(IPv4)
class ARP(Layer):
  ID = "iparp"
  position = 35

  cols = OrderedDict()
  cols['oper'] = 5 # Operation
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
  position = 40

  cols = OrderedDict() # OrderedDict of columns
  cols['ipv4-dst'] = 11
  cols['ipv4-src'] = 11
  cols['ttl'] = 4
  cols['proto'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['ipv4-dst'] = self.pcapToHexStr(data.dst, 2, ".")
    self.vals['ipv4-src'] = self.pcapToHexStr(data.src, 2, ".")
    self.vals['proto'] = self.intToHexStr(data.p).rjust(2, "0")
    self.vals['ttl'] = self.intToHexStr(data.ttl).rjust(2, "0")
    self.vals['off'] = data.off
    self.vals['tos'] = data.tos
    self.vals['len'] = data.len
    self.vals['id'] = data.id

  def toPcap(self):
    rv = dpkt.ip.IP()
    rv.dst = self.hexStrToPcap(self.vals['ipv4-dst'], ".")
    rv.src = self.hexStrToPcap(self.vals['ipv4-src'], ".")
    rv.p = int(self.vals['proto'], 16)
    rv.ttl = int(self.vals['ttl'], 16)
    rv.off = self.vals['off']
    rv.tos = self.vals['tos']
    rv.len = self.vals['len']
    rv.id = self.vals['id']
    return rv

class IGMP(Layer):
  ID = "igmp"
  position = 50

  cols = OrderedDict() # OrderedDict of columns
  cols['type'] = 5
  cols['maxresp'] = 7
  cols['group'] = 11

  def __init__(self, data):
    self.vals = dict()
    self.vals['type'] = self.intToHexStr(data.type).rjust(2, "0")
    self.vals['maxresp'] = self.intToHexStr(data.maxresp).rjust(2, "0")
    self.vals['group'] = self.pcapToHexStr(data.group, 2, ".")

  def toPcap(self):
    rv = dpkt.igmp.IGMP()
    rv.type = int(self.vals['type'])
    rv.maxresp = int(self.vals['maxresp'])
    rv.group = self.hexStrToPcap(self.vals['group'], ".")
    return rv

# Assumes ICMP type is either 0 or 8(echo or echo_reply)
class ICMP(Layer):
  ID = "icmp"
  position = 50

  cols = OrderedDict() # OrderedDict of columns
  cols['type'] = 4
  cols['id'] = 4
  cols['seq'] = 3

  def __init__(self, data):
    self.vals = dict()
    self.vals['type'] = self.intToHexStr(data.type)
    self.vals['id'] = self.intToHexStr(data.data.id)
    self.vals['seq'] = self.intToHexStr(data.data.seq)
    self.vals['data'] = data.data.data

  def toPcap(self):
    rv = dpkt.icmp.ICMP()
    rv.data = dpkt.icmp.ICMP.Echo()
    rv.type = int(self.vals['type'], 16)
    rv.data.id = int(self.vals['id'], 16)
    rv.data.seq = int(self.vals['seq'], 16)
    rv.data.data = self.vals['data']
    return rv

class UDP(Layer):
  ID = "udp"
  position = 50  

  cols = OrderedDict()
  cols['dport'] = 5
  cols['sport'] = 5
  cols['ulen'] = 4

  def __init__(self, data):
    self.vals = dict()
    self.vals['dport'] = self.intToHexStr(data.dport)
    self.vals['sport'] = self.intToHexStr(data.sport)
    self.vals['ulen'] = self.intToHexStr(data.ulen)
    self.vals['data'] = data.data

  def toPcap(self):
    rv = dpkt.udp.UDP()
    rv.dport = int(self.vals['dport'], 16)
    rv.sport = int(self.vals['sport'], 16)
    rv.ulen = int(self.vals['ulen'], 16)
    rv.data = self.vals['data']
    return rv

class TCP(Layer):
  ID = "tcp"
  position = 50

  cols = OrderedDict()
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
