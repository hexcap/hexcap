#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt
import os
import dnet
import pcapy as pcap
import time
import copy

# hexcap specific imports
import cfg
import packet
import layer

# A good default packet to start with
defaultPacket = '\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x86\xdd\x00\x00\x00\x00\x00(\x06\x40\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x02\xcd\xd3\x00\x16\xffP\xd7\x13\x00\x00\x00\x00\xa0\x02\xff\xffg\xd3\x00\x00\x02\x04\x05\xa0\x01\x03\x03\x00\x01\x01\x08\n}\x18:a\x00\x00\x00\x00'

class Capture:
  # Takes a filehandle to a pcap file
  def __init__(self, f=None, name=''):
    self.minSize = self.maxSize = False # These remain False until set
    self.clipboard = [] # Our buffer for yanking and pasting
    self.packets = [] # Our list of packets
    self.fName = name
    self.dataLink = pcap.DLT_EN10MB # Our default datalink

    # Set our default ethernet device
    # TODO: Need more OS's here
    if(os.getuid() or os.geteuid()):
      self.ifName = None
    else:
      osType = os.uname()[0].lower()
      if(osType == "openbsd"):
        self.ifName = "em0"
      elif(osType == "linux"):
        self.ifName = "eth0"
      else:
        self.ifName = "hme0" # Old skool Solaris

      self.iface = dnet.eth(self.ifName)

    if(f):
      self.read(f) # Read in and initialize capture
    else:
      self.packets.append(packet.Packet(self.dataLink, time.time(), defaultPacket, 1))
      
  # Reads a filehandle to a pcap file
  def read(self, f):
    pid = 1
    cap = dpkt.pcap.Reader(f)
    self.dataLink = cap.datalink() # http://www.tcpdump.org/linktypes.html
    for ts, pkt in cap:
      p = packet.Packet(self.dataLink, ts, pkt, pid)
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

  # Appends a packet to our capture with now as timestamp
  def append(self, hdr, pkt):
    self.packets.append(packet.Packet(self.dataLink, time.time(), pkt, len(self.packets) + 1))
    
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
      if(pkt.hasLayer('g')):
        for g in self.expandGenerators(pkt):
          out.writepkt(dpkt.ethernet.Ethernet.pack(g.data()))
      else:
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
    if(len(name.split("/")) > 1):
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

  # Takes a packet obj with generator
  # Returns list of packets with all generators expanded
  def expandGenerators(self, gPkt):
    numPkts = 0
    for lay in gPkt.genLayers: # Determine how many packets to generate
      for col in lay.gen:
        numPkts = max(numPkts, lay.gen[col]['count'])

    if(numPkts == 0 or numPkts == 1):
      return [gPkt]
    else:
      rv = []
      for ii in xrange(numPkts):
        pkt = copy.deepcopy(gPkt)
        pkt.layers.pop(1) # Remove the generator layer
        for lay in pkt.layers[0:]: # Ignore pktID
          for col,gDef in lay.gen.iteritems():
            lay.incColumn(col, (ii % gDef['count']) * gDef['step'])
            del lay.gen[col]['count']
            del lay.gen[col]['step']
            del lay.gen[col]['mask']
          
        rv.append(pkt)
      return rv

  # Function for sending a single packet
  # Takes a packet object to send
  # Returns number of packets sent on success and False on failure
  def tx(self, pkt):
    if(self.dataLink != pcap.DLT_EN10MB):
      return False

    sentPkts = 0
    if(pkt.hasLayer('g')): # It has a generator
      for p in self.expandGenerators(pkt):
        if(self.iface.send(str(p.data())) == -1):
          return False
        else:
          sentPkts += 1
    else:
      if(self.iface.send(str(pkt.data())) == -1):
        return False
      else:
        return 1
    return sentPkts

  # Initializes our pcap capture object
  # Returns a string on failure and None on success 
  def initRx(self, filt):    
    if(os.getuid() or os.geteuid()):
      return "Error:Requires root access"

    if(not self.ifName in pcap.findalldevs()):
      return "Error:Bad interface " + self.ifName

    self.ifCap = pcap.open_live(self.ifName, 65536, True, 10)
    if(self.ifCap.datalink() != pcap.DLT_EN10MB):
      return "Error:Interface not Ethernet " + self.ifName

    if(self.dataLink != pcap.DLT_EN10MB):
      return "Error:Buffer not Ethernet"

    try:
      self.ifCap.setfilter(filt) 
    except pcap.PcapError:
      return "Error:Bad capture filter"

    return None
    
  # Receives a single packet and appends it to capture
  # Must first call initRx()
  def rx(self):
    return self.ifCap.dispatch(1, self.append)

  # Sets both min and max pkt size
  def setPktSizeRange(self, pktMin, pktMax):
    self.minPktSize = pktMin
    self.maxPktSize = pktMax

  # get and set for minSize of every packet in capture
  def _get_minPktSize(self):
    rv = self.packets[0].minSize
    for pkt in self.packets:
      if(rv > pkt.minSize):
        rv = pkt.minSize
    return rv

  def _set_minPktSize(self, s):
    self.minSize = s
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
    self.maxSize = s
    for pkt in self.packets:
      pkt.maxSize = s
  maxPktSize = property(_get_maxPktSize, _set_maxPktSize)
