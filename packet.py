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
import layer

class Packet:
  def __init__(self, ts, packet, pid):
    self.unsupported = False
    self.layers = []
    self.layers.append(layer.PktID(pid))
    self.layers.append(layer.TStamp(ts))
    self.initLayers(dpkt.ethernet.Ethernet(packet))

  # Discover the layers in the packet and construct our layers list
  def initLayers(self, d):
    if(not isinstance(d, dpkt.Packet)):
      return

    if(isinstance(d, dpkt.ethernet.Ethernet)):
      if(hasattr(d, "tag")): # This is a total shit hack
        eth = layer.Ethernet(d)
        eth.vals['etype'] = "8100"
        self.layers.append(eth)
        self.layers.append(layer.Dot1q(d))
      else:
        self.layers.append(layer.Ethernet(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.stp.STP)):
      self.layers.append(layer.STP(d))
      self.initLayers(d.data)

    elif(isinstance(d, dpkt.arp.ARP)):
      self.layers.append(layer.ARP(d))
      self.initLayers(d.data)
                         
    elif(isinstance(d, dpkt.ip.IP)):
      if(d.v == 4):
        self.layers.append(layer.IPv4(d))
        self.initLayers(d.data)
      elif(d.v == 6):
        self.unsupported = True
        self.initLayers(d.data)

    elif(isinstance(d, dpkt.igmp.IGMP)):
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
      self.unsupported = True
      return
      
  # Should never actually get called
  def __getattr__(self, key):
    return None

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

  # Returns the pcap formatted packet
  # Does not work with timestamps
  def data(self):
    for lay in self.layers:
      if(lay.ID == 'pid' or lay.ID == 'tstamp'):
        continue
      elif(isinstance(lay, layer.Ethernet)):
        rv = lay.toPcap()
      else:
        d = rv
        while(isinstance(d.data, dpkt.Packet)):
          d = d.data
        d.data = lay.toPcap()
    return rv

  # For debugging only
  def dump(self):
    rv = ''
    for lay in self.layers:
      rv += "\n" + lay.dump()
    return rv

  def out(self):
    if(self.unsupported):
      return False

    rv = dict()
    for lay in self.layers:
      rv[lay.ID] = lay.vals
    return rv
