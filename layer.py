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
  exposed = False # Is this layer exposed
  exposable = True # Can the exposed boolean be toggled?

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

  # A layer must override this once it becomes RWable
  def toPcap(self):
    return False

  # For debugging only
  def dump(self):
    return repr(self.vals)

# Holds the packet ID ano nothing more
class PktID(Layer):
  ID = "pid"
  RO = True
  exposed = True
  exposable = False
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

# Our generic ethernet class
class Ethernet(Layer):
  position = 10

  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17

  def __init__(self, data):
    self.vals = dict()
    self.vals['eth-dst'] = self.pcapToHexStr(data.dst, 2, ":")
    self.vals['eth-src'] = self.pcapToHexStr(data.src, 2, ":")

  def toPcap(self):
    rv = dpkt.ethernet.Ethernet()
    rv.dst = self.hexStrToPcap(self.vals['eth-dst'], ":")
    rv.src = self.hexStrToPcap(self.vals['eth-src'], ":")
    return rv

# IEEE 802.3 Ethernet II
class EthernetII(Ethernet):
  ID = "ethernet II"

  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17
  cols['etype'] = 5

  def __init__(self, data):
    Ethernet.__init__(self, data)
    self.vals['etype'] = self.intToHexStr(data.type).rjust(4, "0")

  def toPcap(self):
    rv = Ethernet.toPcap(self)
    rv.type = int(self.vals['etype'], 16)
    return rv

# IEEE 802.3 ethernet frame with IEEE 802.2 LLC header
# We do not support IPX yet
class EthernetDot2(Ethernet):
  ID = "ethernet 802.3"

  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17
  cols['len'] = 4
  cols['dsap'] = 4
  cols['ssap'] = 4
#  cols['ctl'] = 3

  def __init__(self, data):
    Ethernet.__init__(self, data)
    self.vals['len'] = self.intToHexStr(data.type).rjust(4, "0")
    self.vals['dsap'] = self.intToHexStr(data.dsap).rjust(2, "0")
    self.vals['ssap'] = self.intToHexStr(data.ssap).rjust(2, "0")
    self.vals['ctl'] = self.intToHexStr(data.ctl).rjust(2, "0")

  def toPcap(self):
    rv = Ethernet.toPcap(self)
    rv.type = int(self.vals['len'], 16)
    rv.dsap = int(self.vals['dsap'], 16)
    rv.ssap = int(self.vals['ssap'], 16)
    rv.ctl = int(self.vals['ctl'], 16)
    return rv

# IEEE 802.3 SNAP 
class EthernetSNAP(Ethernet):
  ID = "ethernet SNAP"

  cols = OrderedDict() # OrderedDict of columns
  cols['eth-dst'] = 17
  cols['eth-src'] = 17
  cols['dsap'] = 4
  cols['ssap'] = 4
  cols['pid'] = 4
#  cols['ctl'] = 3
#  cols['org'] = 6

  # Because of a hack in dpkt 'type' actually refers to the 802.3 SNAP header 'PID'
  def __init__(self, data):
    Ethernet.__init__(self, data)
    self.vals['dsap'] = self.intToHexStr(data.dsap).rjust(2, "0")
    self.vals['ssap'] = self.intToHexStr(data.ssap).rjust(2, "0")
    self.vals['ctl'] = self.intToHexStr(data.ctl).rjust(2, "0")
    self.vals['org'] = self.intToHexStr(data.org).rjust(6, "0")
    self.vals['pid'] = self.intToHexStr(data.type).rjust(4, "0")

  def toPcap(self):
    rv = Ethernet.toPcap(self)
    rv.dsap = int(self.vals['dsap'], 16)
    rv.ssap = int(self.vals['ssap'], 16)
    rv.ctl = int(self.vals['ctl'], 16)
    rv.org = int(self.vals['org'], 16)
    rv.type = int(self.vals['pid'], 16)
    return rv

class Dot1q(Layer):
  ID = "802.1q"
  position = 20

  cols = OrderedDict() # OrderedDict of columns
  cols['tag'] = 5
  cols['1p'] = 5
  cols['etype'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['tag'] = self.intToHexStr(data.tag).rjust(4, "0")
    self.vals['1p'] = self.intToHexStr(data.pcp).rjust(1, "0")
    self.vals['etype'] = self.intToHexStr(data.type).rjust(4, "0")
    self.vals['dei'] = data.dei

  def toPcap(self):
    rv = dpkt.dot1q.DOT1Q()
    rv.tag = int(self.vals['tag'], 16)
    rv.pcp = int(self.vals['1p'], 16)
    rv.type = int(self.vals['etype'], 16)
    rv.dei = self.vals['dei']
    return rv

  def setColumn(self, col, val):
    if(col == '1p'):
      if(0 <= int(val, 16) <= 7):
        self.vals[col] = val
    else:
      self.vals[col] = val

class EDP(Layer):
  ID = "edp"
  position = 20

  cols = OrderedDict() # OrderedDict of columns
  cols['ver'] = 3
  cols['len'] = 4
  cols['seq'] = 4
  cols['mac'] = 17

  def __init__(self, data):
    self.vals = dict()
    self.vals['ver'] = self.intToHexStr(data.v).rjust(2, "0")
    self.vals['len'] = self.intToHexStr(data.len).rjust(4, "0")
    self.vals['seq'] = self.intToHexStr(data.seq).rjust(4, "0")
    self.vals['mac'] = self.pcapToHexStr(data.mac, 2, ":")
    self.vals['data'] = data.data

  def toPcap(self):
    rv = dpkt.edp.EDP()
    rv.v = int(self.vals['ver'], 16)
    rv.len = int(self.vals['len'], 16)
    rv.seq = int(self.vals['seq'], 16)
    rv.mac = self.hexStrToPcap(self.vals['mac'], ":")
    rv.data = self.vals['data']
    return rv

class STP(Layer):
  ID = "stp"
  position = 30

  cols = OrderedDict() # OrderedDict of columns
  cols['root'] = 23
  cols['bridge'] = 23
  cols['port'] = 4
  cols['cost'] = 4
  cols['age'] = 3
  cols['max'] = 3
  cols['hello'] = 5
  cols['delay'] = 5

  def __init__(self, data):
    self.vals = dict()
    self.vals['root'] = self.pcapToHexStr(data.root_id, 2, ":")
    self.vals['bridge'] = self.pcapToHexStr(data.bridge_id, 2, ":")
    self.vals['port'] = self.intToHexStr(data.port_id).rjust(4, "0")
    self.vals['age'] = self.intToHexStr(data.age).rjust(2, "0")
    self.vals['max'] = self.intToHexStr(data.max_age).rjust(2, "0")
    self.vals['hello'] = self.intToHexStr(data.hello).rjust(2, "0")
    self.vals['delay'] = self.intToHexStr(data.fd).rjust(2, "0")
    self.vals['cost'] = self.intToHexStr(data.root_path).rjust(4, "0")
    self.vals['proto-id'] = data.proto_id
    self.vals['ver'] = data.v
    self.vals['type'] = data.type
    self.vals['flags'] = data.flags
    self.vals['data'] = data.data
    cfg.dbg(repr(self.vals))

  def toPcap(self):
    rv = dpkt.stp.STP()
    rv.root_id = self.hexStrToPcap(self.vals['root'], ":")
    rv.bridge_id = self.hexStrToPcap(self.vals['bridge'], ":")
    rv.port_id = int(self.vals['port'], 16)
    rv.age = int(self.vals['age'], 16)
    rv.max_age = int(self.vals['max'], 16)
    rv.hello = int(self.vals['hello'], 16)
    rv.fd = int(self.vals['delay'], 16)
    rv.root_path = int(self.vals['cost'], 16)
    rv.proto_id = self.vals['proto-id']
    rv.v = self.vals['ver']
    rv.type = self.vals['type']
    rv.flags = self.vals['flags']
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
    self.vals['hl'] = data.hl
    self.vals['v'] = data.v
    self.vals['off'] = data.off
    self.vals['tos'] = data.tos
    self.vals['len'] = data.len
    self.vals['id'] = data.id
    self.vals['opts'] = data.opts

  def toPcap(self):
    rv = dpkt.ip.IP()
    rv.dst = self.hexStrToPcap(self.vals['ipv4-dst'], ".")
    rv.src = self.hexStrToPcap(self.vals['ipv4-src'], ".")
    rv.p = int(self.vals['proto'], 16)
    rv.ttl = int(self.vals['ttl'], 16)
    rv.hl =  self.vals['hl']
    rv.v =  self.vals['v']
    rv.off = self.vals['off']
    rv.tos = self.vals['tos']
    rv.len = self.vals['len']
    rv.id = self.vals['id']
    rv.opts = self.vals['opts']
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
    rv.type = int(self.vals['type'], 16)
    rv.maxresp = int(self.vals['maxresp'], 16)
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
