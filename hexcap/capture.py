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

# hexcap specific imports
import cfg
import packet
import layer

class Capture:
  # Takes a filehandle to a pcap file
  def __init__(self, f, name=''):
    self.clipboard = [] # Our buffer for yanking and pasting
    if(len(name) > 0):
      self.fName = name
    self.read(f)

  # Reads a filehandle to a pcap file
  def read(self, f):
    self.packets = []
    pid = 1
    cap = dpkt.pcap.Reader(f)
    for ts, pkt in cap:
      p = packet.Packet(ts, pkt, pid)
      self.packets.append(p)
      pid += 1

  # Is our entire capture RWable?
  def _RW(self):
    for pkt in self.packets:
      if(not pkt.RW):
        return False
    return True
  RW = property(_RW)

  # For debugging only
  def dump(self):
    rv = ""
    for pkt in self.packets:
      rv += pkt.dump() + "\n"
    return rv

  # Writes our capture to the passed filehandle
  # Not meant to be called externally
  # Should raise IOError if problems but pcap.Writer does not support it
  def __write(self, f):
    out = dpkt.pcap.Writer(f)
    for pkt in self.packets:
      out.writepkt(dpkt.ethernet.Ethernet.pack(pkt.data()))

  # Saves our capture file
  # Raises IOError if problems
  def save(self):
    try:
      f = open(self.fName, 'wb')
    except:
      raise IOError
    else:
      self.__write(f)
      f.close()
      
  # Changes our save file to passed arg and then saves to it
  # Raises IOError if problems
  def saveAs(self, name):
    try:
      f = open(name, 'wb')
    except:
      raise IOError
    else:
      f.close()
      self.fName = name
      self.save()
        
  # Yanks packets from main capture and puts them in the clipboard
  # Takes inclusive first and last packets to be yanked as integers(zero based)
  def yank(self, first, last):
    self.clipboard = []
    for ii in xrange(first, last + 1):
      if(first >= len(self.packets)):
        self.clipboard.append(self.packets.pop())
      else:
        self.clipboard.append(self.packets.pop(first))
    self.resetPIDs(first)

    # Clobber PIDs of yanked packets (Defensive programming)
    for pkt in self.clipboard:
      for lay in pkt.layers:
        if(lay.ID == 'pid'):
          lay.setColumn('pid', -1)

  # Pastes packets from our clipboard to our main capture
  # Takes the packet at the paste point as an integer(zero based)
  def paste(self, first):
    for ii in xrange(0, len(self.clipboard)):
      self.packets.insert(first + ii, self.clipboard[ii])  
    self.resetPIDs(first)

  # Resets pktIDs from first to end
  # Takes starting packet as integer
  def resetPIDs(self, first):
    for ii in xrange(first, len(self.packets)):
      for lay in self.packets[ii].layers:
        if(lay.ID == 'pid'):
          lay.setColumn('pid', ii + 1)

  # get and set for minSize of every packet in capture
  def _get_minPktSize(self):
    rv = self.packets[0].minSize
    for pkt in self.packets:
      if(rv > pkt.minSize):
        rv = pkt.minSize
    return rv
  def _set_minPktSize(self, s):
    for pkt in self.packets:
      pkt.minSize = s
  minPktSize = property(_get_minPktSize, _set_minPktSize)

  # get and set for maxSize of every packet in capture
  def _get_maxPktSize(self):
    rv = 0
    for pkt in self.packets:
      if(rv < pkt.maxSize):
        rv = pkt.maxSize
    return rv
  def _set_maxPktSize(self, s):
    for pkt in self.packets:
      pkt.maxSize = s
  maxPktSize = property(_get_maxPktSize, _set_maxPktSize)
