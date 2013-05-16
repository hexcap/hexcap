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
import layer

class Packet:
  def __init__(self, ts, packet, pid):
    self.packet = packet # Should only be used for debugging
    self.unsupported = False
    self.layers = []
    self.layers.append(layer.PktID(pid))
    self.layers.append(layer.TStamp(ts))

    dPkt = dpkt.ethernet.Ethernet(packet)
    self.layers.append(layer.Ethernet(dPkt))
    self.layEType(dPkt)

  # Should never actually get called
  def __getattr__(self, key):
    return None

  # Sets the value of section,column to val
  def setColumn(self, sid, col, val):
    for lay in self.layers:
      if(lay.sName == sid):
        lay.setColumn(col, val)

  # Returns PID of packet
  def getPID(self):
    for lay in self.layers:
      if(lay.sName == 'pid'):
        return lay.c['pid']

  # Returns the pcap formatted packet
  # Does not work with timestamps
  def data(self):
    for lay in self.layers:
      if(lay.sName == 'pid' or lay.sName == 'tstamp'):
        continue
      elif(lay.sName == 'ethernet'):
        p = lay.toPcap()
      else:
        d = p
        while(len(d.data) != 0):
          d = d.data
        d.data = lay.toPcap()
    return p

  # Possibly inaccurate debug dump of pcap info
  def dump(self):
    return repr(dpkt.ethernet.Ethernet(self.packet))

  def layEType(self, eth):
    eType = hex(eth.type)

    if(eType == "0x8100"):
      self.layDot1x(eth.data)
    elif(eType == "0x800"):
      self.layIP4(eth.data)
    elif(eType == "0x806"):
      self.layIPARP(eth.data)
    else:
      self.eType = False

  def layDot1x(self, dot1x):
    self.layers.append(layer.Dot1x(dot1x))
    self.unsupported = True

  def layIPARP(self, iparp):
    self.layers.append(layer.IPARP(iparp))
    self.unsupported = True

  def layIP4(self, ip4):
    self.layers.append(layer.IPv4(ip4))
    if(ip4.p == 1):
      self.layICMP(ip4.data)
    elif(ip4.p == 6):
      self.layTCP(ip4.data)
    elif(ip4.p == 17):
      self.layUDP(ip4.data)
    else:
      self.ip4Only = True

  def layICMP(self, icmp):
    self.layers.append(layer.ICMP(icmp))

  def layTCP(self, tcp):
    self.layers.append(layer.TCP(tcp))

  def layUDP(self, udp):
    self.layers.append(layer.UDP(udp))
    self.unsupported = True

  def out(self):
    if(self.unsupported):
      dbg("Aborting:Unsupported Packet")
      return False

    rv = dict()
    for lay in self.layers:
      rv[lay.sName] = lay.c
    return rv
