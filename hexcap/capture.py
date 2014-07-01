#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import sys
sys.path.insert(0, '../dpkt/')
import dpkt
import os
import dnet
import pcapy as pcap
import time

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

    # Set our default ethernet device
    # TODO: Need more OS's here
    if(os.getuid() or os.geteuid()):
      self.ifName = None
    else:
      osType = os.uname()[0].lower()
      if(osType == "openbsd"):
        self.ifName = "em1"
      elif(osType == "linux"):
        self.ifName = "eth0"
      else:
        self.ifName = "hme0" # Old skool Solaris

      self.iface = dnet.eth(self.ifName)

    self.filter = '' # Init our configured BPF capture filter
    self.read(f) # Read in and initialize capture

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

  def __len__(self):
    return len(self.packets)

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
  # We don't create directories, only files if they do not exist
  # Raises IOError if problems
  def saveAs(self, name):
    name = name.strip()

    # Check that directory exists
    if(name.split("/")):
      if(not os.path.isdir(os.path.split(name)[0])):
        return "Error:Directory does not exist"

    try:
      f = open(name, 'wb')
    except:
      return "Error:Cannot open file"
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

  # Sets both min and max pkt size
  def setPktSizeRange(self, pktMin, pktMax):
    self.minPktSize = pktMin
    self.maxPktSize = pktMax

  # Sets the interface for sending and capturing
  def setInterface(self, name):
    name = name.strip()

    if(os.getuid() or os.geteuid()):
      return "Error:Requires root access"

    try:
      iface = dnet.eth(name)
    except:
      return "Error:Interface does not exist"

    try:
      iface.get()
    except:
      return "Error:Interface has no MAC"

    self.ifName = name
    self.iface = dnet.eth(self.ifName)

  # Private function for sending a single packet
  # Takes a packet object to send
  # Returns True on success and false on failure
  def _sendPkt(self, pkt):
    if(self.iface.send(str(pkt.data())) == -1):
      return False
    else:
      return True

  # Sends an inclusive range of packets
  # Takes first pkt ID, last pkt ID and iterations to send it
  # Passed pkt IDs are one's based from user's perspective
  # Returns err msg on failure, num pkts sent msg on success
  def sendRange(self, first, last, iterations):
    if(os.getuid() or os.geteuid()):
      return "Error:Requires root access"

    fail = False
    pktSent = 0

    # Convert from user's 1-based numbering to our 0-based numbering, and handle bad user input
    first -= 1
    last -= 1

    if(first <= last): # User wants normal ordering
      if(first < 0):
        first = 0
      if(last > len(self.packets) - 1):
        last =  len(self.packets) - 1
      pkts = []
      for jj in xrange(first, last+1):
        pkts.append(jj)

    else: # User wants reverse ordering
      if(last < 0):
        last = 0
      if(first > len(self.packets) - 1):
        first =  len(self.packets) - 1
      pkts = []
      for jj in xrange(first, last-1, -1):
        pkts.append(jj)

    for ii in xrange(iterations):
      for jj in pkts:
        if(self._sendPkt(self.packets[jj])):
          pktSent += 1
        else:
          fail = True
        
    if(fail):
      return "Error:One or more packets failed to send"
    else:
      return str(pktSent) + " packets egressed " + self.ifName
    
  # Captures a single packet and appends it to capture
  # Returns a string on failure and None on success
  def captureAppend(self):

    # Appends a packet to our capture
    def appendPacket(hdr, pkt):
      p = packet.Packet(time.time(), pkt, len(self.packets))
      self.packets.append(p)

    if(os.getuid() or os.geteuid()):
      return "Error:Requires root access"

    if(not self.ifName in pcap.findalldevs()):
      return "Error:Bad interface " + self.ifName

    # ifCap = pcap.open_live(self.ifName, dnet.intf().get(self.ifName)['mtu'], True, 10)
    ifCap = pcap.open_live(self.ifName, 65536, True, 10)
    if(ifCap.datalink() != pcap.DLT_EN10MB):
      return "Error:Interface not Ethernet " + self.ifName

    ifCap.setfilter(self.filter)
    cfg.dbg("Blocking:" + str(ifCap.getnonblock()))
    cfg.dbg("ifType:" + str(ifCap.datalink()))

    # ifCap.loop(1, lambda hdr,pkt: cfg.dbg("hdr:" + repr(hdr) + "pkt:" + repr(pkt)))
    return ifCap.loop(1, appendPacket)

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
