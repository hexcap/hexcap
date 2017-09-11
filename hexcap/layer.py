#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

# For now we just let dpkt do all the checksum calculations
# So it's not possible to create packets with invalid checksums
# AND any packets opened with invalid checksums will have them corrected at save time

import cfg
import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt
from collections import OrderedDict
import math

class Layer:
  # cols holds width in displayed characters for each column, inclusive any delimiters
  cols = OrderedDict()

  # delim holds lists of columns which require delimiters
  # Format of list is [delimter, field_width]
  delim = {}

  RO = False # Is this layer read-only?
  exposed = True # Is this layer exposed
  exposable = True # Can the exposed boolean be toggled?

  def __init__(self):
    self.vals = {} # Holds values for each column
    self.gen = {} # Holds generators for each column

  # Convert int to hex without leading 0x
  def intToHexStr(self, num):
    x,rv = hex(num).split("0x")
    return rv

  # Change pcap character data to padded hex string without leading 0x
  def binToHexStr(self, val):
    return hex(ord(val)).split("0x")[1].rjust(2, "0")

  # Change dpkt character bytes to string hex values of length ln with a delimiter of delim
  # ln corresponds to how many nibbles you want between each delim
  def pcapToHexStr(self, bytes, delim, ln=2):
    rv = ""
    trv = ""
    for b in bytes:
      trv += self.binToHexStr(b)
      if(len(trv) >= ln):
        rv += trv + delim
        trv = ""
    return rv.rstrip(delim)

  # Change string hex values to dpkt character bytes ignoring delimiter of delim
  def hexStrToPcap(self, s, delim, ln=2):
    rv = ""
    bytes = s.split(delim)

    if(ln != 2):
      if((ln % 2 != 0) or (ln < 2)):
        return False
      else:
        newbytes = []
        for b in bytes:
           for ii in xrange(0, ln, 2):
            newbytes.append(b[ii:ii+2])
        bytes = newbytes

    for b in bytes:
      rv += chr(int(b, 16))
    return rv

  # Delimites passed string s with delimiter delim with ln characters between each delim
  # May also pass a prepending string rv
  # Returns delimited string
  def delimStr(self, s, delim, ln=2, rv=''):
    for ii in xrange(0, len(s), ln):
      rv += s[ii:ii+ln] + delim
    return rv.strip(delim)

  # Delimites value based on existence of delim key
  # Takes a string to be delimited and a column to use for the delim key
  # Returns delimited column value as string
  def delimCol(self, s, col):
    if(not (col in self.delim)):
      return s
    else:
      return self.delimStr(s, self.delim[col][0], self.delim[col][1])

  # Adds a generator to a col
  # Takes column to add it to; then count and step for the generator
  def addGenerator(self, col, count, step):
    if(not col in self.gen):
      self.gen[col] = {'count': count, 'step': step, 'mask': self.delimCol(''.join('0' * (len(cfg.cleanHexStr(self.vals[col])))), col)}
    else:
      self.gen[col]['count'] = count
      self.gen[col]['step'] = step

  # Adds a mask to a col
  # Takes column to add it to, and binary mask to be added
  # Mask is always stored as delimted hexStr
  def addMask(self, col, mask):
    colLen = len(cfg.cleanHexStr(self.vals[col])) * 4
    if(len(mask) > colLen):
      return "Error:Mask is too long"
    else: # Pad our mask with either 0s or 1s to fill entire column
      if(mask.endswith('0')):
        mask = mask.ljust(colLen, '0')
      else:
        mask = mask.ljust(colLen, '1')

    mask = self.delimCol(cfg.binStrToHexStr(mask), col)
    if(not col in self.gen):
      self.gen[col] = {'count': 0, 'step': 0, 'mask': mask}
    else:
      self.gen[col]['mask'] = mask

  # Sets column to val
  def setColumn(self, col, val):
    self.vals[col] = val

  # Increment passed column by x respecting any set mask
  # x can be any positive or negative integer
  def incColumn(self, col, x):
    self.vals[col] = cfg.incHexStr(self.vals[col], self.gen[col]['mask'], x)

  # A layer must override this once it becomes RWable
  def toPcap(self):
    return False

  # For debugging only
  def __repr__(self):
    return repr(self.vals)

  def __str__(self):
    return self.__repr__()

# Holds the packet ID and nothing more
class PktID(Layer):
  ID = "pid"
  RO = True
  exposable = False
  position = 0
  
  cols = OrderedDict() 
  cols['pid'] = cfg.pktIDWidth

  def __init__(self, pid):
    Layer.__init__(self)
    self.vals['pid'] = str(pid).rjust(cfg.pktIDWidth, "0")

  # Overriding virtual since we're picky about pid
  def setColumn(self, col, val):
    if(val == -1): # Fill PID with ?'s if we get passed -1
      self.vals[col] = ''
      for ii in xrange(0, cfg.pktIDWidth):
        self.vals[col] += "?"
    else:
      self.vals[col] = str(val).rjust(cfg.pktIDWidth, "0")

# Generic/Container class for control syntax elements
# The Control layer holds the type of the syntax element contained within the packet
# It also holds the argument for that control statement
# If a packet has any generator, sleep or jump; it MUST have a Control layer
# The value of column 'c' MUST be either 'g', 's', or 'j'
class Control(Layer):
  ID = "cntrl"
  RO = True
  position = 1 # If this layer exists it MUST be in position 1, we assume this in many places

  cols = OrderedDict()
  cols['c'] = 3
  cols['arg'] = cfg.pktIDWidth

  def __init__(self, t, arg=''):
    Layer.__init__(self)
    self.vals['c'] = format(t, '^' + str(self.cols['c']))
    self.vals['arg'] = format(str(arg), '^' + str(self.cols['arg']))  

# Timestamp layer
class TStamp(Layer):
  ID = "tstamp"
  RO = True
  position = 5

  cols = OrderedDict() 
  cols['tstamp'] = 13
    
  def __init__(self, ts):
    Layer.__init__(self)
    self.vals['tstamp'] = "{:.2f}".format(ts)

  def toPcap(self):
    return float(self.vals['tstamp'])

# A layer to hold our unsupported protocol components
class Leftovers(Layer):
  ID = "Undefined"
  RO = True # For now, undefined layers are Read-Only
  position = 99
  uWidth = 20 # Somewhat arbitrary width in nibbles
  dotWidth = 2 # How many trailing dots?

  cols = OrderedDict() 
  cols['undefined'] = uWidth

  def __init__(self, data):
    Layer.__init__(self)
    self.data = data # We store the actual data here

    s = self.pcapToHexStr(data.pack(), ":", len(data.pack()))
    if(s > self.uWidth):
      s = s[:self.uWidth - self.dotWidth]
      for ii in xrange(self.dotWidth):
        s += "."
      self.vals['undefined'] = s
    else:
      self.vals['undefined'] = s.ljust(self.uWidth, "x")

  def toPcap(self):
    return self.data

# Our generic ethernet class
class Ethernet(Layer):
  position = 10

  cols = OrderedDict() 
  cols['dst'] = 17
  cols['src'] = 17

  delim = {}
  delim['dst'] = [':', 2]
  delim['src'] = [':', 2]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['dst'] = self.pcapToHexStr(data.dst, ":")
    self.vals['src'] = self.pcapToHexStr(data.src, ":")

  def toPcap(self):
    rv = dpkt.ethernet.Ethernet()
    rv.dst = self.hexStrToPcap(self.vals['dst'], ":")
    rv.src = self.hexStrToPcap(self.vals['src'], ":")
    return rv

# IEEE 802.3 Ethernet II
class EthernetII(Ethernet):
  ID = "ethernet II"

  cols = OrderedDict() 
  cols['dst'] = 17
  cols['src'] = 17
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

  cols = OrderedDict() 
  cols['dst'] = 17
  cols['src'] = 17
  cols['len'] = 4
  cols['dsap'] = 4
  cols['ssap'] = 4
  cols['ctl'] = 3

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
    rv.org = True
    return rv

# IEEE 802.3 SNAP 
class EthernetSNAP(Ethernet):
  ID = "ethernet SNAP"

  cols = OrderedDict() 
  cols['dst'] = 17
  cols['src'] = 17
  cols['dsap'] = 4
  cols['ssap'] = 4
  cols['pid'] = 4

  # Because of a hack in dpkt 'type' actually refers to the 802.2 SNAP header 'PID'
  def __init__(self, data):
    Ethernet.__init__(self, data)
    self.vals['dsap'] = self.intToHexStr(data.dsap).rjust(2, "0")
    self.vals['ssap'] = self.intToHexStr(data.ssap).rjust(2, "0")
    self.vals['ctl'] = self.intToHexStr(data.ctl).rjust(2, "0")
    self.vals['org'] = self.intToHexStr(data.org).rjust(6, "0")
    self.vals['pid'] = self.intToHexStr(data.type).rjust(4, "0")
    self.vals['plen'] = data.plen

  def toPcap(self):
    rv = Ethernet.toPcap(self)
    rv.dsap = int(self.vals['dsap'], 16)
    rv.ssap = int(self.vals['ssap'], 16)
    rv.ctl = int(self.vals['ctl'], 16)
    rv.org = int(self.vals['org'], 16)
    rv.type = int(self.vals['pid'], 16)
    rv.plen = self.vals['plen']
    return rv

# IEEE 802.11 WLAN
# Very basic
class Dot11(Layer):
  ID = "802.11"
  position = 10

  cols = OrderedDict() 
  cols['ver'] = 4
  cols['type'] = 4
  cols['subt'] = 4
  cols['to'] = 4
  cols['from'] = 4
  cols['wep'] = 4

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['ver'] = self.intToHexStr(data.version)
    self.vals['type'] = self.intToHexStr(data.type)
    self.vals['subt'] = self.intToHexStr(data.subtype)
    self.vals['to'] = self.intToHexStr(data.to_ds)
    self.vals['from'] = self.intToHexStr(data.from_ds)
    self.vals['more_frag'] = self.intToHexStr(data.more_frag)
    self.vals['retry'] = self.intToHexStr(data.retry)
    self.vals['pwr'] = self.intToHexStr(data.pwr_mgt)
    self.vals['more_data'] = self.intToHexStr(data.more_data)
    self.vals['wep'] = self.intToHexStr(data.wep)
    self.vals['order'] = self.intToHexStr(data.order)

  def toPcap(self):
    rv = dpkt.ieee80211.IEEE80211()()
    rv.version = int(self.vals['ver'], 16)
    rv.type = int(self.vals['type'], 16)
    rv.subtype = int(self.vals['subt'], 16)
    rv.to_ds = int(self.vals['to'], 16)
    rv.from_ds = int(self.vals['from'], 16)
    rv.more_frag = int(self.vals['more_frag'], 16)
    rv.retry = int(self.vals['retry'], 16)
    rv.pwr_mgt = int(self.vals['pwr'], 16)
    rv.more_data = int(self.vals['more_data'], 16)
    rv.wep = int(self.vals['wep'], 16)
    rv.order = int(self.vals['order'], 16)
    return rv

# IEEE 802.1q
class Dot1q(Layer):
  ID = "802.1q"
  position = 20

  cols = OrderedDict() 
  cols['tag'] = 5
  cols['1p'] = 5
  cols['etype'] = 5

  def __init__(self, data):
    Layer.__init__(self)
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
      Layer.setColumn(self, col, val)

# Cisco Discovery Protocol
class CDP(Layer):
  ID = "cdp"
  position = 20

  cols = OrderedDict()
  cols['ver'] = 3
  cols['ttl'] = 3

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['ver'] = self.intToHexStr(data.version).rjust(2, "0")
    self.vals['ttl'] = self.intToHexStr(data.ttl).rjust(2, "0")
    self.vals['data'] = data.data

  def toPcap(self):
    rv = dpkt.cdp.CDP()
    rv.version = int(self.vals['ver'], 16)
    rv.ttl = int(self.vals['ttl'], 16)
    rv.data = self.vals['data']
    return rv

# Extreme Discovery Protocol
class EDP(Layer):
  ID = "edp"
  position = 20

  delim = {}
  delim['mac'] = [':', 2]

  cols = OrderedDict()
  cols['ver'] = 3
  cols['len'] = 4
  cols['seq'] = 4
  cols['mac'] = 17

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['ver'] = self.intToHexStr(data.v).rjust(2, "0")
    self.vals['len'] = self.intToHexStr(data.hlen).rjust(4, "0")
    self.vals['seq'] = self.intToHexStr(data.seq).rjust(4, "0")
    self.vals['mac'] = self.pcapToHexStr(data.mac, ":")
    self.vals['res'] = data.res
    self.vals['mid'] = data.mid    
    self.vals['data'] = data.data

  def toPcap(self):
    rv = dpkt.edp.EDP()
    rv.v = int(self.vals['ver'], 16)
    rv.hlen = int(self.vals['len'], 16)
    rv.seq = int(self.vals['seq'], 16)
    rv.mac = self.hexStrToPcap(self.vals['mac'], ":")
    rv.res = self.vals['res']
    rv.mid = self.vals['mid']
    rv.data = self.vals['data']
    return rv

# Spanning Tree Protocol
class STP(Layer):
  ID = "stp"
  position = 30

  cols = OrderedDict() 
  cols['root'] = 23
  cols['bridge'] = 23
  cols['port'] = 4
  cols['cost'] = 4
  cols['age'] = 3
  cols['max'] = 3
  cols['hello'] = 5
  cols['delay'] = 5

  delim = {}
  delim['root'] = [':', 2]
  delim['bridge'] = [':', 2]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['root'] = self.pcapToHexStr(data.root_id, ":")
    self.vals['bridge'] = self.pcapToHexStr(data.bridge_id, ":")
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

# Adress Resolution Protocol for IPv4
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
  
  delim = {}
  delim['sha'] = [':', 2]
  delim['tha'] = [':', 2]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['oper'] = self.intToHexStr(data.op).rjust(4, "0")
    self.vals['sha'] = self.pcapToHexStr(data.sha, ":")
    self.vals['tha'] = self.pcapToHexStr(data.tha, ":")
    self.vals['spa'] = self.pcapToHexStr(data.spa, ".")
    self.vals['tpa'] = self.pcapToHexStr(data.tpa, ".")

  def toPcap(self):
    rv = dpkt.arp.ARP()
    rv.op = int(self.vals['oper'], 16)
    rv.sha = self.hexStrToPcap(self.vals['sha'], ":")
    rv.tha = self.hexStrToPcap(self.vals['tha'], ":")
    rv.spa = self.hexStrToPcap(self.vals['spa'], ".")
    rv.tpa = self.hexStrToPcap(self.vals['tpa'], ".")
    return rv

# Internet Protocol version 4
class IPv4(Layer):
  ID = "ipv4"
  position = 40

  cols = OrderedDict() 
  cols['dst'] = 11
  cols['src'] = 11
  cols['tos'] = 4
  cols['df'] = 4
  cols['ttl'] = 4
  cols['proto'] = 5

  delim = {}
  delim['dst'] = ['.', 2]
  delim['src'] = ['.', 2]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['dst'] = self.pcapToHexStr(data.dst, ".")
    self.vals['src'] = self.pcapToHexStr(data.src, ".")
    self.vals['proto'] = self.intToHexStr(data.p).rjust(2, "0")
    self.vals['ttl'] = self.intToHexStr(data.ttl).rjust(2, "0")
    self.vals['tos'] = self.intToHexStr(data.tos).rjust(2, "0")

    # Dpkt just gives 'off', so we must determine 'df' ourselves
    self.vals['off'] = self.intToHexStr(data.off & 8191).rjust(2, "0")
    self.vals['df'] = self.intToHexStr(data.off >> 13)

    self.vals['hl'] = self.intToHexStr(data.hl)
    self.vals['v'] = self.intToHexStr(data.v)
    self.vals['len'] = self.intToHexStr(data.len)
    self.vals['id'] = self.intToHexStr(data.id)
    self.vals['opts'] = data.opts

  def toPcap(self):
    rv = dpkt.ip.IP()
    rv.dst = self.hexStrToPcap(self.vals['dst'], ".")
    rv.src = self.hexStrToPcap(self.vals['src'], ".")
    rv.p = int(self.vals['proto'], 16)
    rv.ttl = int(self.vals['ttl'], 16)
    rv.tos = int(self.vals['tos'], 16)
    rv.off = (int(self.vals['df'], 16) << 13) | int(self.vals['off'], 16)

    rv.hl = int(self.vals['hl'], 16)
    rv.v = int(self.vals['v'], 16)
    rv.len = int(self.vals['len'], 16)
    rv.id = int(self.vals['id'], 16)
    rv.opts = self.vals['opts']
    return rv

  def setColumn(self, col, val):
    if(col == 'df'):
      if(0 <= int(val, 16) <= 7):
        self.vals[col] = val
    else:
      Layer.setColumn(self, col, val)

# Internet Protocol Version 6
class IPv6(Layer):
  ID = "ipv6"
  position = 40
  
  cols = OrderedDict() 
  cols['dst'] = 39
  cols['src'] = 39
  cols['tc'] = 4
  cols['flow'] = 5
  cols['ttl'] = 4
  cols['proto'] = 5

  delim = {}
  delim['dst'] = [':', 4]
  delim['src'] = [':', 4]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['dst'] = self.pcapToHexStr(data.dst, ":", 4)
    self.vals['src'] = self.pcapToHexStr(data.src, ":", 4)
    self.vals['proto'] = self.intToHexStr(data.nxt).rjust(2, "0")
    self.vals['ttl'] = self.intToHexStr(data.hlim).rjust(2, "0")
    self.vals['tc'] = self.intToHexStr(data.fc).rjust(2, "0")
    self.vals['flow'] = self.intToHexStr(data.flow).rjust(5, "0")
    self.vals['v'] = data.v
    self.vals['len'] = data.plen

  def toPcap(self):
    rv = dpkt.ip6.IP6()
    rv.dst = self.hexStrToPcap(self.vals['dst'], ":", 4)
    rv.src = self.hexStrToPcap(self.vals['src'], ":", 4)
    rv.nxt = int(self.vals['proto'], 16)
    rv.hlim = int(self.vals['ttl'], 16)
    rv.fc = int(self.vals['tc'], 16)
    rv.flow = int(self.vals['flow'], 16)
    rv.v =  self.vals['v']
    rv.plen = self.vals['len']

    # See dpkt ip6.py for explanation
    rv.extension_hdrs = dict()
    for hdr in dpkt.ip6.ext_hdrs:
      rv.extension_hdrs[hdr] = None
    return rv

# Internet Group Management Protocol v1/v2
# We do not currently support v3
class IGMP(Layer):
  ID = "igmp"
  position = 50

  cols = OrderedDict() 
  cols['type'] = 5
  cols['maxresp'] = 7
  cols['group'] = 11

  delim = {}
  delim['group'] = ['.', 2]

  def __init__(self, data):
    Layer.__init__(self)
    self.vals['type'] = self.intToHexStr(data.type).rjust(2, "0")
    self.vals['maxresp'] = self.intToHexStr(data.maxresp).rjust(2, "0")
    self.vals['group'] = self.pcapToHexStr(data.group, ".")

  def toPcap(self):
    rv = dpkt.igmp.IGMP()
    rv.type = int(self.vals['type'], 16)
    rv.maxresp = int(self.vals['maxresp'], 16)
    rv.group = self.hexStrToPcap(self.vals['group'], ".")
    return rv

# Internet Control Message Protocol
# Assumes ICMP type is either 0 or 8(echo or echo_reply)
class ICMP(Layer):
  ID = "icmp"
  position = 50

  cols = OrderedDict() 
  cols['type'] = 4
  cols['id'] = 4
  cols['seq'] = 3

  def __init__(self, data):
    Layer.__init__(self)
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

# User Datagram Protocol
class UDP(Layer):
  ID = "udp"
  position = 50  

  cols = OrderedDict()
  cols['dport'] = 5
  cols['sport'] = 5
  cols['ulen'] = 4

  def __init__(self, data):
    Layer.__init__(self)
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

# Transport Control Protocol
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
    Layer.__init__(self)
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

# These tests are horribly outdated and unmaintained
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
