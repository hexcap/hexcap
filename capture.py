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
sys.path.insert(0, '/home/smutt/hacking/python/hexcap/dpkt-read-only/')
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

  # For debugging only
  def dump(self):
    rv = ""
    for pkt in self.packets:
      rv += pkt.dump() + "\n"
    return rv

  # Writes our capture to the passed filehandle
  def write(self, f):
    out = dpkt.pcap.Writer(f)
    for pkt in self.packets:
      out.writepkt(dpkt.ethernet.Ethernet.pack(pkt.data()))

  # Yanks packets from main capture and puts them in the clipboard
  # Takes inclusive first and last packets to be yanked as integers(zero based)
  def yank(self, first, last):
    #    cfg.dbg("Capture_yank len_packets:" + str(len(self.packets)) + " len_clipboard:" + str(len(self.clipboard)) + \
        #" first:" + str(first) + " last:" + str(last))
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
    #    cfg.dbg("Capture_paste len_packets:" + str(len(self.packets)) + " len_clipboard:" + str(len(self.clipboard)) + " first:" + str(first))
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
