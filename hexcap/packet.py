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
sys.path.insert(0, '../dpkt-read-only/')
import dpkt
import layer

class Packet:
  def __init__(self, ts, packet, pid):
    self.unsupported = False
    self.layers = []
    self.layers.append(layer.PktID(pid))
    self.layers.append(layer.TStamp(ts))

    self.leftovers = None
    self.minSize = len(packet)
    self.maxSize = max(dpkt.ethernet.ETH_MTU, len(packet))
    self.initLayers(dpkt.ethernet.Ethernet(packet))

  # Is every layer of this packet writable
  # TODO:Add more checks in the future
  def _RW(self):
    for lay in self.layers:
      if(lay.ID == 'pid' or lay.ID == 'tstamp'):
        continue
      elif(not lay.toPcap()):
        if(not self.leftovers):
          return False
    return True
  RW = property(_RW)

  # Discover the layers in the packet and construct our layers list
  def initLayers(self, d):
    if(not isinstance(d, dpkt.Packet)):
      return

    if(isinstance(d, dpkt.ethernet.Ethernet)):
      if(d.type == 0x0800 or d.type == 0x8100 or d.type == 0x86dd):
        self.layers.append(layer.EthernetII(d)) # Ethernet II
        self.initLayers(d.data)
      elif(hasattr(d, 'dsap')):
        if((d.dsap == 170 or d.dsap == 171) and (d.ssap == 170 or d.ssap == 171)):
          self.layers.append(layer.EthernetSNAP(d)) # SNAP
          self.initLayers(d.data)
        else:
          self.layers.append(layer.EthernetDot2(d)) # 802.2
          self.initLayers(d.data)
      else:
        self.unsupport(d)
        return

    elif(isinstance(d, dpkt.cdp.CDP)):
      self.layers.append(layer.CDP(d))
      return

    elif(isinstance(d, dpkt.edp.EDP)):
      self.layers.append(layer.EDP(d))
      return

    elif(isinstance(d, dpkt.dot1q.DOT1Q)):
      self.layers.append(layer.Dot1q(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.stp.STP)):
      self.layers.append(layer.STP(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.arp.ARP)):
      self.layers.append(layer.ARP(d))
      self.initLayers(d.data)
                         
    elif(isinstance(d, dpkt.ip.IP)):
      self.layers.append(layer.IPv4(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.ip6.IP6)):
      self.layers.append(layer.IPv6(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.igmp.IGMP)):
      if(d.type == 0x22): # IGMPv3
        self.unsupport(d)
        return
      else:
        self.layers.append(layer.IGMP(d))
        self.initLayers(d.data)

    elif(isinstance(d, dpkt.icmp.ICMP)):
      self.layers.append(layer.ICMP(d))
      return

    elif(isinstance(d, dpkt.tcp.TCP)):
      self.layers.append(layer.TCP(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.udp.UDP)):
      self.layers.append(layer.UDP(d))
      self.initLayers(d.data)

    else:
      self.unsupport(d)
      return

  # Mark a packet as unsupported and save the leftovers
  def unsupport(self, d):
    self.unsupported = True
    self.leftovers = d
  
  # Sets the value of section,column to val
  def setColumn(self, sid, col, val):
    for lay in self.layers:
      if(lay.ID == sid):
        lay.setColumn(col, val)

  # Convenience method
  # Returns PID of packet
  def getPID(self):
    for lay in self.layers:
      if(lay.ID == 'pid'):
        return lay.vals['pid']

  # Convenience method
  # Returns timestamp of packet
  def getTS(self):
    for lay in self.layers:
      if(isinstance(TStamp, lay)):
        return lay.vals['tstamp']

  # Convenience method
  # Return True if passed sid corresponds with layer in pkt
  # Else returns False
  def hasLayer(self, sid):
    for lay in self.layers:
      if(lay.ID == sid):
        return True
    return False

  # Returns the dpkt packet object
  # Does not work with timestamps
  # Returns False if pcap data cannot be constructed
  def data(self):
    for lay in self.layers:
      if(lay.ID == 'pid' or lay.ID == 'tstamp'):
        continue
      elif(isinstance(lay, layer.Ethernet)):
        rv = lay.toPcap()
      else:
        rv = self.pushDpktLayer(rv, lay.toPcap())
    if(self.unsupported):
      rv = self.pushDpktLayer(rv, self.leftovers)
      return rv
    else:
      return self.sizePkt(rv)

  # Totally unpythonic but don't care
  # Takes a dpktObj and pushes a new layer onto it
  # We're basically just treating the dpkt object like a stack
  def pushDpktLayer(self, dpktObj, lay):
    d = dpktObj
    while(isinstance(d.data, dpkt.Packet)):
      d = d.data
    d.data = lay
    return dpktObj

  # Pads our pcap packet and returns False on packets greater than MTU
  def sizePkt(self, pkt):
    if((len(pkt) >= self.minSize) & (len(pkt) <= self.maxSize)):
      return pkt
    elif(len(pkt) > self.maxSize):
      raise PacketError, "Packet to write larger than MTU"
    else:
      d = pkt
      while(isinstance(d.data, dpkt.Packet)):
        d = d.data
      for ii in xrange(len(pkt), self.minSize):
        d.data += '\x00'
    return pkt

  # For debugging only
  def __repr__(self):
    rv = ''
    for lay in self.layers:
      rv += "\n" + lay.ID + repr(lay)
    return rv

  def __str__(self):
    return self.__repr__()

  def out(self):
    rv = dict()
    if(self.unsupported):
      rv['pid'] = self.layers[0].vals
      rv['tstamp'] = self.layers[1].vals
      rv['unsupported'] = True
      return rv

    for lay in self.layers:
      rv[lay.ID] = lay.vals
    return rv

class PacketError(Exception):
  pass
