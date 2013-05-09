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

import os
import math
import curses
import locale
import time
import sys
import dpkt
from collections import OrderedDict

# hexcap specific imports
import cfg
import packet
import layer

def usage(s):
  print "FATAL ERROR: " + s
  print ""
  print "USAGE: edpcap.py FILE"
  print "FILE must be a valid pcap file"
  sys.exit(1)

# Returns table width of the entire table
# Summation of all visible sections widths
def tableWidth():
  rv = 0
  for s in displayedSections():
    rv += s.width
  return max(1, rv - 1)

# Returns an ordered list of displayed sections
# A section is displayed if('present' && 'visible' == True)
def displayedSections():
  rv = []
  for s in sections:
    if(s.visible and s.present):
      rv.append(s)
  return rv

# Returns header section that cursor X value is currently in
# Takes X value of cursor
def cursorSection(x):
  dSections = displayedSections()
  totX = 0
  for s in dSections:
    if(x < totX + s.width):
      return s
    else:
      totX += s.width
  return dSections.reversed.next()

# Returns header section and column that cursor X value is currently in
# Takes X value of cursor
def cursorColumn(x):
  totX = 0
  for s in displayedSections():
    if(x < totX + s.width - 1):
      for col, cWidth in s.c.iteritems():
        if(x < totX + cWidth):
          return list((s, col))
        else:
          totX += cWidth + 1
    else:
      totX += s.width

# Returns leftmost absolute X value for passed section name
# Returns False on failure
def sectionLeft(sid):
  rv = 0
  for s in displayedSections():
    if(s.id == sid):
      return rv
    else:
      rv += s.width
  return False

# Returns leftmost absolute X value(after divider) for passed section and column name
# Returns False on failure
def columnLeft(sid, cid):
  rv = sectionLeft(sid)
  for s in displayedSections():
    if(s.id == sid):
      for col, width in s.c.iteritems():
        if(col == cid):
          return rv
        else:
          rv += width + 1
  return False

# Returns rightmost absolute X value(before divider) for passed section and column name
def columnRight(sid, cid):
  for s in displayedSections():
    if(s.id == sid):
      return columnLeft(sid, cid) + s.c[cid] - 1

# Returns center absolute X value for passed section name
# Returns False on failure
def sectionCenter(sid):
  rv = 0
  for s in displayedSections():
    if(s.id == sid):
      return rv + (int(math.floor(s.width / 2)))
    else:
      rv += s.width
  return False

# Debugging output
def dbg(str):
  if(cfg.debug):
    dbgF.write(str + '\n')

class Section:
  def __init__(self, sectId):
    self.id = sectId
    self.c = OrderedDict() # OrderedDict of columns
    self.width = 0 # Width of complete section
    self.present = False # Is this section present in our capture?
    self.visible = True # Is this section currently visible?
    self.RO = False # Is this section ReadOnly? Can it be modified by the user

  def __len__(self):
    return len(self.c)

#  def __iter__(self):

  def __getitem__(self, key):
    return self.c[key]
  
  def __setitem__(self, key, value):
    self.c[key] = value

  def __contains__(self, item):
    if item in c:
      return True
    else:
      return False

  def __missing__(self, key):
    return False

  def append(self, name, w):
    self.c[name] = w
    self.width += w + 1

pid = Section('pid')
pid.append('pid', cfg.pktIDWidth)
pid.RO = True

tstamp = Section('tstamp')
tstamp.append('tstamp', 13)
tstamp.RO = True

ethernet = Section('ethernet')
ethernet.append('eth-dst', 17)
ethernet.append('eth-src', 17)
ethernet.append('etype', 5)

ipv4 = Section('ipv4')
ipv4.append('ipv4-dst', 11)
ipv4.append('ipv4-src', 11)
ipv4.append('proto', 5)

icmp = Section('icmp')
icmp.append('type', 4)
icmp.append('sum', 4)
icmp.append('id', 4)
icmp.append('seq', 3)

tcp = Section('tcp')
tcp.append('dport', 5)
tcp.append('sport', 5)
tcp.append('seq', 8)
tcp.append('ack', 8)
tcp.append('win', 4)

sections = list((pid, tstamp, ethernet, ipv4, icmp, tcp))

# Our wrapper class for an ncurses screen
class EdScreen:

  def __init__(self):
    locale.setlocale(locale.LC_ALL, '')
    self.code = locale.getpreferredencoding()
    self.stdscr = curses.initscr()
    curses.noecho()
    curses.raw()
    self.stdscr.keypad(1)

    self.headerRows = 2 # Section / Column names
    self.miniBufferRows = 2 # Includes blank line

    # Cursor inits
    self.maxY, self.maxX = self.stdscr.getmaxyx()
    self.cY = 2
    self.cX = 0

    # Our stack of hidden sections
    self.hiddenSectNames = []

    # Are we in insert mode?
    self.insert = False

  # Initializes our ncurses pad
  # Takes a Capture object
  def initPad(self, cap):
    self.cap = cap
    self.ppadTopY = self.headerRows # Topmost ppad position on screen
    self.ppadBottomY = self.maxY - self.miniBufferRows # Bottommost ppad position on screen
    self.ppadCurY = 0 # Current topmost visible line in ppad
    self.ppadCols = self.maxX # Width of screen
    self.ppadRows = len(self.cap.packets) # Total number of lines in ppad 
    self.ppad = curses.newpad(self.ppadRows, self.ppadCols)

    self.drawPpad()
    self.refresh()

  # Completely redraws our ppad and determines which sections are present
  # Sets self.displayTableWidth
  def drawPpad(self):
    for p in self.cap.packets:
     for s in sections:
        if(s.id in p.out()):
          s.present = True

    self.displayTableWidth = 0 # Width of displayed columns
    for s in sections:
      if(s.present and s.visible):
        if(self.displayTableWidth + s.width <= self.maxX):
          self.displayTableWidth += s.width
        else:
          break

    self.ppad.clear()
    y = 0
    for p in self.cap.packets:
      self.drawPktLine(y, p.out())
      y += 1

  def refresh(self):
    if(curses.is_term_resized(self.maxY, self.maxX)):
      dbg("Caught resize event. Consider using immedok()")
      self.tearDown()

    self.ppadRightX = tableWidth()
    self.drawHeader()
    self.drawFooter()
    self.stdscr.move(self.cY, self.cX)
    self.refreshBoldPacket()
    self.ppad.refresh(self.ppadCurY, 0, self.ppadTopY, 0, self.ppadBottomY, self.ppadRightX)
    self.stdscr.refresh()
    curses.doupdate()

  def refreshBoldPacket(self):
#    dbg("refreshBoldPacket ppadCurY:" + str(self.ppadCurY) + " len(cap.packets):" + str(len(self.cap.packets)))
    boldPkt = self.ppadCurY + self.cY - self.ppadTopY
    if(boldPkt == 0): # First packet in ppad
      self.drawPktLine(boldPkt, self.cap.packets[boldPkt].out(), True)
      if(len(self.cap.packets) > 1):
        self.drawPktLine(boldPkt + 1, self.cap.packets[boldPkt + 1].out())
        
    elif(self.cY == self.ppadTopY - 1): # Top packet on screen
      self.drawPktLine(boldPkt, self.cap.packets[boldPkt].out(), True)
      self.drawPktLine(boldPkt + 1, self.cap.packets[boldPkt + 1].out())

    elif((self.cY == self.ppadBottomY - 1) or (len(self.cap.packets) == boldPkt + 1)): # Bottom packet on screen
      self.drawPktLine(boldPkt - 1, self.cap.packets[boldPkt - 1].out())
      self.drawPktLine(boldPkt, self.cap.packets[boldPkt].out(), True)

    else: # Middle packet on screen
      self.drawPktLine(boldPkt - 1, self.cap.packets[boldPkt - 1].out())
      self.drawPktLine(boldPkt, self.cap.packets[boldPkt].out(), True)
      self.drawPktLine(boldPkt + 1, self.cap.packets[boldPkt + 1].out())

  # Draws a packet line onto our ppad
  # Takes a y value and list of cells that correlates to our global header list
  def drawPktLine(self, y, row, bold=False):
#    dbg("drawPktLine y:" + str(y) + " pkt:" + str(row['pid']['pid']) + " bold:" + str(bold) \
#    + " displayTableWidth:" + str(self.displayTableWidth))

    x = 0
    for s in sections:
      if(s.visible and s.present):
        if(self.displayTableWidth >= x + s.width):
          for colName, width in s.c.iteritems():
            if(s.id in row):
              if(bold):
                self.ppad.addstr(y, x, row[s.id][colName].rjust(width) + "|", curses.A_BOLD)
              else:
                self.ppad.addstr(y, x, row[s.id][colName].rjust(width) + "|")
                  
              x += width + 1
            else:
              if(s.present):
                self.ppad.addstr(y, x, " ".rjust(width + 1))
                x += width + 1
        else:
          return

  # Draws our top 2 header rows
  def drawHeader(self):
    x0 = 0
    x1 = 0
    for s in sections:
      sectId = s.id
      if(s.visible and s.present):
        if(self.displayTableWidth >= x0 + s.width):
          for column, width in s.c.iteritems():
            col = column.center(width, " ")
            self.stdscr.addstr(1, x1, col + "|", curses.A_REVERSE)
            x1 += width + 1

          head = "{" + sectId + "}"
          head = head.center(s.width - 1, " ") + "|"
          self.stdscr.addstr(0, x0, head)
          x0 += s.width
        else:
          return

  def drawFooter(self):
    y = self.maxY - self.miniBufferRows
    fName = "[" + self.cap.fName + "]"
    divider = 3
    posWidth = 6

    self.stdscr.hline(y, 0, "-", divider)
    x = divider

    self.stdscr.addstr(y, x, fName)
    x += len(fName)

    self.stdscr.hline(y, x, "-", divider)
    x += divider

    self.stdscr.addstr(y, x, "[y:" + str(self.cY).rjust(3))
    x += posWidth

    self.stdscr.addstr(y, x, " x:" + str(self.cX).rjust(3))
    x += posWidth

    txt = " p:" + str(self.ppadCurY + self.cY - self.ppadTopY + 1).rjust(3) + "/" + str(len(self.cap.packets)) + "]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    self.stdscr.hline(y, x, "-", divider)
    x += divider

    if(self.insert):
      txt = "[INS]"
    else:
      txt = "[NAV]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    self.stdscr.hline(y, x, "-", divider)
    x += divider

    s,c = cursorColumn(self.cX)
    if(s.RO):
      txt = "[" + s.id + "/RO]"
    else:
      txt = "[" + s.id + "/RW]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    if(self.displayTableWidth > x):
      self.stdscr.hline(y, x, "-", self.displayTableWidth - x)

  # Handles pageUp and pageDown
  def page(self, dY):
    if(self.ppadBottomY >= self.ppadRows):
      return

    ppadPos = self.cY - self.ppadTopY + self.ppadCurY
    self.drawPktLine(ppadPos, self.cap.packets[ppadPos].out())

    if(dY > 0):
      ppadHeight = self.ppadBottomY - self.ppadTopY
      if(self.ppadCurY + ppadHeight < self.ppadRows):
        self.ppadCurY = min(self.ppadRows - ppadHeight, self.ppadCurY + dY)
      else:
        self.cY = self.ppadBottomY - 1
        
    else:
      if(self.ppadCurY > 0):
        self.ppadCurY = max(self.ppadCurY + dY, 0)
      else:
        self.cY = self.ppadTopY

  # Moves cursor right and left by columns
  def shiftColumn(self, cols):
    if(cols == 0):
      return

    sect, col = cursorColumn(self.cX)
    if(cols > 0):
      if(self.cX + sect.c[col] < self.displayTableWidth - 1):
        self.cX = columnLeft(sect.id, col)
        for cName, cWidth in sect.c.iteritems():
          if(cName == col):
            self.cX += cWidth + 1

        self.shiftColumn(cols - 1)
      else:
        curses.flash()
        curses.napms(10)
        return
    else:
      if(self.cX - sect.c[col] >= 0):
        self.cX = columnRight(sect.id, col)
        for cName, cWidth in sect.c.iteritems():
          if(cName == col):
            self.cX -= cWidth + 1

        self.shiftColumn(cols + 1)
      else:
        curses.flash()
        curses.napms(10)
        return

  # Moves our cursor, takes deltaY and deltaX, one delta value MUST be 0 and the other MUST NOT be 0
  def move(self, dY, dX):
    if(dY != 0):
      if(dY > 0):
        if(self.cY + dY < self.ppadBottomY):
          if(self.cY + self.ppadCurY <= len(self.cap.packets)):
            self.cY += dY
        else:
          if(self.ppadCurY + self.ppadBottomY - self.ppadTopY < self.ppadRows):
            self.ppadCurY += 1
      else:
        if(self.cY + dY >= self.ppadTopY):
          self.cY += dY
        elif(self.cY + dY == self.ppadTopY - 1):
          if(self.ppadCurY > 0):
            self.ppadCurY -= 1

    elif(dX != 0):
      if(dX > 0):
        if(self.cX + dX < self.displayTableWidth - 1):
          self.cX += dX
      else:
        if(self.cX + dX >= 0):
          self.cX += dX

  def hideSection(self):
    if(len(displayedSections()) > 1):
      s = cursorSection(self.cX)
      s.visible = False
      self.hiddenSectNames.append(s.id)
      self.stdscr.clear()
      self.drawPpad() # Sets self.displayTableWidth
      self.cX = min(self.cX, self.displayTableWidth - 2)
      self.refresh()

  def unhideLastSection(self):
    if(len(self.hiddenSectNames) > 0):
      sectId = self.hiddenSectNames.pop()
      for s in sections:
        if(s.id == sectId):
          s.visible = True
          self.cX = sectionCenter(sectId)
      self.stdscr.clear()
      self.drawPpad()
      self.refresh()

  def toggleInsert(self):
    if(self.insert == True):
      self.insert = False
    else:
      self.insert = True

  def getch(self):
    return self.stdscr.getch()

  # Takes ppad relative y,x coordinates
  # Returns list((int)attributes, (chr)character) at that location on our ppad
  def inch(self, y, x):
    inpt = hex(self.ppad.inch(y, x))
    return list((int(inpt[2:4], 16), chr(int(inpt[4:], 16))))

  # Handles our character insertion
  # Modifies column then increments cursor X position by 1
  def handleInsert(self, c):
    ppadCY = self.ppadCurY + self.cY - self.ppadTopY
    attr,char = self.inch(ppadCY, self.cX)
    if(ord(char) not in cfg.hexChars): # immutable character
      self.move(0, 1)
      return

    sect,col = cursorColumn(self.cX)
    if(sect.RO): # ReadOnly section
      return

    leftX = columnLeft(sect.id, col)
    rightX = columnRight(sect.id, col)

    val = ""
    for x in xrange(leftX, rightX + 1):
      if(x == self.cX):
        val += chr(c)
      else:
        attr,char = self.inch(ppadCY, x)
        val += char

    # We assume packets are in order and start at zero
    self.cap.packets[ppadCY].setColumn(sect.id, col, val)
    self.move(0, 1)

  def tearDown(self):
    self.stdscr.keypad(0)
    curses.echo()
    curses.endwin()
    sys.exit(0)

  # Not yet implemented
  def markSet(self):
    return False

  def yank(self):
    return False

  def paste(self):
    return False

  def yankPacket(self):
    return False

class Capture:
  # Takes a filehandle to a pcap file
  def __init__(self, f, name=''):
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

  def dump(self):
    rv = ""
    for pkt in self.packets:
      rv += pkt.dump() + "\n"
    return rv

  # Writes our capture to the passed filehandle
  def write(self, f):
    out = dpkt.pcap.Writer(f)
    for pkt in self.packets:
      out.writepkt(pkt.data())


###########################
# BEGIN PROGRAM EXECUTION #
###########################
if(cfg.debug):
  dbgF = open('hexcap.log', 'a', 0)
  
# Check for bad args
if(len(sys.argv) != 2): usage("Insufficient Arguments")
if(not os.path.exists(sys.argv[1])): usage("Bad Filename")
fName = sys.argv[1]

# Initialize
f = open(fName, 'rb')
pc = Capture(f, fName)
f.close()

mainScr = EdScreen()
mainScr.initPad(pc)

while True:
  try:
    mainScr.refresh()
    c = mainScr.getch()

    if(c != -1):
      dbg("KeyPress:" + str(c))

      if(mainScr.insert):
        if(c in cfg.hexChars):
          mainScr.handleInsert(c)

      if(c == curses.KEY_RIGHT):
        mainScr.move(0, 1)

      elif(c == curses.KEY_LEFT):
        mainScr.move(0, -1)

      elif(c == curses.KEY_UP):
        mainScr.move(-1, 0)

      elif(c == curses.KEY_DOWN):
        mainScr.move(1, 0)

      elif(c == cfg.KEY_CTRL_F): # Page Down
        mainScr.page(10)

      elif(c == cfg.KEY_CTRL_B): # Page Up
        mainScr.page(-10)

      elif(c == cfg.KEY_CTRL_S): # Save file
        f = open(pc.fName, 'wb')
        pc.write(f)
        f.close()

      elif(c == ord("<")): # Shift left 1 column
        mainScr.shiftColumn(-1)

      elif(c == ord(">")): # Shift right 1 column
        mainScr.shiftColumn(1)

      elif(c == cfg.KEY_CTRL_H): # Hide section
        mainScr.hideSection()

      elif(c == cfg.KEY_CTRL_U): # Unhide last hidden section
        mainScr.unhideLastSection()

      elif(c == cfg.KEY_CTRL_R): # Reread packet capture from disk
        fName = pc.fName
        f = open(fName, 'rb')
        pc = Capture(f, fName)
        f.close()
        mainScr.initPad(pc)

      elif(c == cfg.KEY_CTRL_I): # Toggle insert mode
        mainScr.toggleInsert()

      elif(c == cfg.KEY_CTRL_SPACE): # Set new mark
        mainScr.markSet()

      elif(c == cfg.KEY_CTRL_Y): # Paste packet(s)
        mainScr.paste()

      elif(c == cfg.KEY_CTRL_W): # Yank packets
        mainScr.yank()

      elif(c == cfg.KEY_CTRL_K): # Yank packet
        mainScr.yankPacket()

      elif(c == cfg.KEY_CTRL_Q or c == ord("q")):
        if(cfg.debug):
          dbgF.close()
        mainScr.tearDown()

  except KeyboardInterrupt:
    mainScr.tearDown()
    if(cfg.debug):
      dbgF.close()
  
