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
import sys
sys.path.insert(0, '/home/smutt/hacking/python/hexcap/dpkt-read-only/')
import dpkt
from collections import OrderedDict

# hexcap specific imports
import cfg
import capture
import packet
import layer
import section

# Our wrapper class for an ncurses screen
class EdScreen:

  def __init__(self):
    locale.setlocale(locale.LC_ALL, '')
    self.code = locale.getpreferredencoding()
    self.stdscr = curses.initscr()
    curses.noecho()
    curses.raw()
    self.stdscr.keypad(1)

    self.headerHeight = 2 # Section / Column names
    self.footerHeight = 2 # Includes blank line

    # Cursor inits
    self.maxY, self.maxX = self.stdscr.getmaxyx()
    self.cY = 2
    self.cX = 0

    # Our stack of hidden sections
    self.hiddenSectIDs = []

    # Are we in insert mode?
    self.insert = False

    # Packet ID of marked packet. One based.
    self.mark = 0

  def tearDown(self):
    self.stdscr.keypad(0)
    curses.echo()
    curses.endwin()
    sys.exit(0)

  # Initializes our ncurses pad
  # Takes a Capture object
  def initPad(self, cap):
    self.cap = cap
    self.ppadTopY = self.headerHeight # Topmost ppad position on screen
    self.ppadBottomY = self.maxY - self.footerHeight # Bottommost ppad position on screen
    self.ppadCurY = 0 # Current topmost visible line in ppad
    self.ppadRows = len(self.cap.packets) # Total number of lines in ppad 
    self.ppad = curses.newpad(self.ppadRows, self.maxX)
    self.buildSections()
    self.drawPpad()
    self.refresh()

  # Completely redraws our ppad and rebuilds our section list
  # Sets displayTableWidth
  def drawPpad(self):
    if(self.ppadRows != len(self.cap.packets)): # Our capture has changed in size
      self.ppadRows = len(self.cap.packets)
      self.ppad = curses.newpad(self.ppadRows, self.maxX)
      self.buildSections()

    # Set displayTableWidth 
    self.displayTableWidth = 0 # Width of displayed columns(zero based)
    for s in self.sections:
      if(s.visible):
        if(self.displayTableWidth + s.width <= self.maxX):
          self.displayTableWidth += s.width
        else:
          break

    # Draw our ppad
    self.stdscr.clear()
    self.ppad.clear()
    y = 0
    for p in self.cap.packets:
      self.drawPktLine(y, p.out())
      y += 1

  def refresh(self):
    if(curses.is_term_resized(self.maxY, self.maxX)):
      cfg.dbg("Caught resize event. Consider using immedok()")
      self.tearDown()
    
    self.drawHeader()
    self.drawFooter()
    self.stdscr.move(self.cY, self.cX)
    self.refreshBoldPacket()
    self.ppad.refresh(self.ppadCurY, 0, self.ppadTopY, 0, self.ppadBottomY, self.tableWidth)
    self.stdscr.refresh()
    curses.doupdate()

  # Determines the correct order of sections to display based on capture
  def buildSections(self):
    self.sections = []
    IDs = [] # Holds temp list of sections we've added to self.sections
    for pkt in self.cap.packets:
      for lay in pkt.layers:
        if(not(lay.ID in IDs)):
          IDs.append(lay.ID)

          # Construct our new section
          s = section.Section(lay.ID)
          for col,width in lay.cols.iteritems():
            s.append(col, width)
          s.RO = lay.RO # non-default values for layers need to be handled here

          # append/insert our new section
          if(len(self.sections) == 0):
            self.sections.append(s)
          else:
            for ii in xrange(len(pkt.layers)):
              if(ii >= len(self.sections)):
                self.sections.append(s)
                break
              elif(pkt.layers[ii].ID != self.sections[ii].ID):
                self.sections.insert(ii + 1, s)
                break

  # Relative Y cursor position in our ppad
  def _get_ppadCY(self):
    return self.ppadCurY + self.cY - self.ppadTopY
  ppadCY = property(_get_ppadCY)

  # An ordered list of displayed sections
  def _get_displayedSections(self):
    rv = []
    for s in self.sections:
      if(s.visible):
        rv.append(s)
    return rv
  displayedSections = property(_get_displayedSections)

  # Table width of the entire displayed table
  def _get_tableWidth(self):
    rv = 0
    for s in self.displayedSections:
      rv += s.width
    return max(1, rv - 1)
  tableWidth = property(_get_tableWidth)

  # Returns header section that cursor X value is currently in
  # Takes X value of cursor
  def cursorSection(self, x):
    dSections = self.displayedSections
    totX = 0
    for s in dSections:
      if(x < totX + s.width):
        return s
      else:
        totX += s.width
    return dSections.reversed.next()

  # Returns header section and column that cursor X value is currently in
  # Takes X value of cursor
  def cursorColumn(self, x):
    totX = 0
    for s in self.displayedSections:
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
  def sectionLeft(self, sid):
    rv = 0
    for s in self.displayedSections:
      if(s.ID == sid):
        return rv
      else:
        rv += s.width
    return False

  # Returns leftmost absolute X value(after divider) for passed section and column name
  # Returns False on failure
  def columnLeft(self, sid, cid):
    rv = self.sectionLeft(sid)
    for s in self.displayedSections:
      if(s.ID == sid):
        for col, width in s.c.iteritems():
          if(col == cid):
            return rv
          else:
            rv += width + 1
    return False

  # Returns rightmost absolute X value(before divider) for passed section and column name
  def columnRight(self, sid, cid):
    for s in self.displayedSections:
      if(s.ID == sid):
        return self.columnLeft(sid, cid) + s.c[cid] - 1

  # Returns center absolute X value for passed section name
  # Returns False on failure
  def sectionCenter(self, sid):
    rv = 0
    for s in self.displayedSections:
      if(s.ID == sid):
        return rv + (int(math.floor(s.width / 2)))
      else:
        rv += s.width
    return False

  # Handle regular refreshing of packet lines
  #    cfg.dbg("refreshBoldPacket ppadCY:" + str(self.ppadCY) + " mark:" + str(self.mark))
  def refreshBoldPacket(self):
    if(len(self.cap.packets) == 0):
      return
    elif(len(self.cap.packets) == 1):
      if(self.mark == 1):
        self.drawPktLine(0, self.cap.packets[0].out(), True, True)
      else:
        self.drawPktLine(0, self.cap.packets[0].out(), True, False)
      return

    if(self.mark):
      self.drawPktLine(self.ppadCY, self.cap.packets[self.ppadCY].out(), False, True)

      if(self.ppadCY < self.mark - 1): # Cursor is above mark
        if(self.ppadCY > 0):
          self.drawPktLine(self.ppadCY - 1, self.cap.packets[self.ppadCY - 1].out())
        for pkt in xrange(self.mark - 1, self.ppadCY + 1, -1):
          self.drawPktLine(pkt, self.cap.packets[pkt].out(), False, True)
        if(self.mark <= len(self.cap.packets) - 1):
          self.drawPktLine(self.mark, self.cap.packets[self.mark].out())

      elif(self.ppadCY == self.mark - 1): # Cursor is on mark
        if(self.mark > 1):
          self.drawPktLine(self.ppadCY - 1, self.cap.packets[self.ppadCY - 1].out()) 
        if(self.mark <= len(self.cap.packets) - 1):
          self.drawPktLine(self.ppadCY + 1, self.cap.packets[self.ppadCY + 1].out())

      elif(self.ppadCY > self.mark - 1): # Cursor is below mark
        if(self.mark > 1):
          self.drawPktLine(self.mark - 2, self.cap.packets[self.mark - 2].out()) 
        for pkt in xrange(self.mark - 1, self.ppadCY + 1):
          self.drawPktLine(pkt, self.cap.packets[pkt].out(), False, True)
        if(self.ppadCY < len(self.cap.packets) - 1):
            self.drawPktLine(self.ppadCY + 1, self.cap.packets[self.ppadCY + 1].out())

    else:
      self.drawPktLine(self.ppadCY, self.cap.packets[self.ppadCY].out(), True)

      if(self.ppadCY == 0): # First packet in ppad
        if(len(self.cap.packets) > 1):
          self.drawPktLine(1, self.cap.packets[1].out())
        
      elif(self.cY == self.ppadTopY - 1): # Top packet on screen
        self.drawPktLine(self.ppadCY + 1, self.cap.packets[self.ppadCY + 1].out())

      elif((self.cY == self.ppadBottomY - 1) or (len(self.cap.packets) == self.ppadCY + 1)): # Bottom packet on screen
        self.drawPktLine(self.ppadCY - 1, self.cap.packets[self.ppadCY - 1].out())

      else: # Middle packet on screen
        self.drawPktLine(self.ppadCY - 1, self.cap.packets[self.ppadCY - 1].out())
        self.drawPktLine(self.ppadCY + 1, self.cap.packets[self.ppadCY + 1].out())

  # Draws a packet line onto our ppad
  # Takes a y value and list of cells that correlates to our global header list
  #    cfg.dbg("y:" + str(y) + " pid:" + str(row['pid']['pid']) + " bold:" + str(bold) + " rev:" + str(reverse))
  def drawPktLine(self, y, row, bold=False, reverse=False):
    x = 0
    for s in self.sections:
      if(s.visible):
        if(self.displayTableWidth >= x + s.width):
          for colName, width in s.c.iteritems():
            if(s.ID in row):
              if(reverse):
                self.ppad.addstr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_REVERSE)
              else:
                if(bold):
                  self.ppad.addstr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_BOLD)
                else:
                  self.ppad.addstr(y, x, row[s.ID][colName].rjust(width) + "|")
                  
              x += width + 1
            else:
              self.ppad.addstr(y, x, " ".rjust(width + 1))
              x += width + 1
        else:
          return

  # Draws our top 2 header rows
  def drawHeader(self):
    x0 = 0
    x1 = 0
    for s in self.sections:
      if(s.visible):
        if(self.displayTableWidth >= x0 + s.width):
          for column, width in s.c.iteritems():
            col = column.center(width, " ")
            self.stdscr.addstr(1, x1, col + "|", curses.A_REVERSE)
            x1 += width + 1

          head = "{" + s.ID + "}"
          head = head.center(s.width - 1, " ") + "|"
          self.stdscr.addstr(0, x0, head)
          x0 += s.width
        else:
          return

  def drawFooter(self):
    y = self.maxY - self.footerHeight
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

    if(self.mark):
      txt = "[MRK]"
    elif(self.insert):
      txt = "[INS]"
    else:
      txt = "[NAV]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    self.stdscr.hline(y, x, "-", divider)
    x += divider

    s,c = self.cursorColumn(self.cX)
    if(s.RO):
      txt = "[" + s.ID + "/" + c + "/RO]"
    else:
      txt = "[" + s.ID + "/" + c + "/RW]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    if(self.displayTableWidth > x):
      self.stdscr.hline(y, x, "-", self.displayTableWidth - x)

  # Prints text to the mini-buffer 
  def printToMiniBuffer(self, s):
    self.stdscr.addstr(self.maxY - 1, 0, s.strip()[:self.maxX])
    
  # Clears minibuffer
  def clearMiniBuffer(self):
    self.stdscr.hline(self.maxY - 1, 0, " ", self.maxX)

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

  # Moves cursor right and left by cols columns
  def shiftColumn(self, cols):
    if(cols == 0):
      return

    sect, col = self.cursorColumn(self.cX)
    if(cols > 0):
      if(self.cX + sect.c[col] < self.displayTableWidth - 1):
        self.cX = self.columnLeft(sect.ID, col)
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
        self.cX = self.columnRight(sect.ID, col)
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
    if(len(self.displayedSections) > 1):
      s = self.cursorSection(self.cX)
      s.visible = False
      self.hiddenSectIDs.append(s.ID)
      self.drawPpad() # Sets self.displayTableWidth
      self.cX = min(self.cX, self.displayTableWidth - 2)
      self.refresh()

  def unhideLastSection(self):
    if(len(self.hiddenSectIDs) > 0):
      sectId = self.hiddenSectIDs.pop()
      for s in self.sections:
        if(s.ID == sectId):
          s.visible = True
          self.cX = self.sectionCenter(sectId)
      self.drawPpad()
      self.refresh()

  def toggleInsert(self):
    if(self.mark): # Cannot enter insert mode with mark set
      return

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
    attr,char = self.inch(self.ppadCY, self.cX)
    if(ord(char) not in cfg.hexChars): # immutable character
      self.move(0, 1)
      return

    sect,col = self.cursorColumn(self.cX)
    if(sect.RO): # ReadOnly section
      return

    leftX = self.columnLeft(sect.ID, col)
    rightX = self.columnRight(sect.ID, col)

    val = ""
    for x in xrange(leftX, rightX + 1):
      if(x == self.cX):
        val += chr(c)
      else:
        attr,char = self.inch(self.ppadCY, x)
        val += char

    self.cap.packets[self.ppadCY].setColumn(sect.ID, col, val)
    self.move(0, 1)

  def toggleMark(self):
    if(self.insert): # Cannot set mark in insert mode
      return

    if(self.mark):
      self.mark = 0
      self.drawPpad()
      self.refresh()
    else:
      self.mark = self.ppadCY + 1

  # Called after an action MAY cause cY or cX to be in illegal position
  # Returns cY and cX to legal position(s)
  def resetCursor(self):
    # Handle X
    if(self.cX > self.displayTableWidth):
      self.cX = self.displayTableWidth

    # Handle Y
    if(len(self.cap.packets) <= 1):
      self.cY = self.ppadTopY

    elif(self.cY < self.ppadTopY):
      self.cY = self.ppadTopY

    elif(self.cY > self.ppadBottomY):
      self.cY = self.ppadBottomY

    elif(self.cY + self.ppadCurY >= len(self.cap.packets)):
      self.cY = self.ppadTopY + len(self.cap.packets) - 1

  #    cfg.dbg("Edscreen_yank len_packets:" + str(len(self.cap.packets)) + " len_clipboard:" + str(len(self.cap.clipboard)) + \
  #    " ppadCY:" + str(self.ppadCY) + " mark:" + str(self.mark)))
  def yank(self):
    if(not self.mark):
      return

    if(self.ppadCY <= self.mark - 1):
      self.cap.yank(self.ppadCY, self.mark - 1)
    else:
      self.cap.yank(self.mark - 1, self.ppadCY)
      self.cY -= len(self.cap.clipboard) - 1

    self.mark = 0
    self.resetCursor()
    self.drawPpad()
    self.refresh()

  def paste(self):
    if(len(self.cap.clipboard) == 0):
      return

    self.cap.paste(self.ppadCY)
    self.cY += len(self.cap.clipboard)
    self.resetCursor()
    self.drawPpad()
    self.refresh()

###########################
# BEGIN PROGRAM EXECUTION #
###########################

def usage(s):
  print "FATAL ERROR: " + s
  print ""
  print "USAGE: edpcap.py FILE"
  print "FILE must be a valid pcap file"
  sys.exit(1)

# Check for bad args
if(len(sys.argv) != 2): usage("Insufficient Arguments")
if(not os.path.exists(sys.argv[1])): usage("Bad Filename")
fName = sys.argv[1]

# Initialize
try:
  f = open(fName, 'rb')
except:
  usage("Unable to open file for reading >> " + fName)

pc = capture.Capture(f, fName)
f.close()

mainScr = EdScreen()
mainScr.initPad(pc)

while True:
  try:
    mainScr.refresh()
    c = mainScr.getch()
    mainScr.clearMiniBuffer()

    if(c != -1):
      cfg.dbg("KeyPress:" + str(c))

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
        writeError = False
        try:
          f = open(pc.fName, 'wb')
        except:
          writeError = True
          mainScr.printToMiniBuffer("ERROR: Unable to open file for writing >> " + pc.fName)

        if(not writeError):
          writeError = False
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
        readError = False
        try:
          f = open(pc.fName, 'rb')
        except:
          readError = True
          mainScr.printToMiniBuffer("ERROR: Unable to open file for reading >> " + pc.fName)

        if(not readError):
          readError = False
          pc = Capture(f, pc.fName)
          f.close()
          mainScr.initPad(pc)

      elif(c == cfg.KEY_CTRL_I): # Toggle insert mode
        mainScr.toggleInsert()

      elif(c == cfg.KEY_CTRL_SPACE): # Set new mark
        mainScr.toggleMark()

      elif(c == cfg.KEY_CTRL_Y): # Paste packet(s)
        mainScr.paste()

      elif(c == cfg.KEY_CTRL_W): # Yank packets
        mainScr.yank()

      elif(c == cfg.KEY_CTRL_K): # Yank packet
        mainScr.yankPacket()

      elif(c == cfg.KEY_CTRL_Q or c == ord("q")):
        if(cfg.debug):
          cfg.dbgF.close()
        mainScr.tearDown()

  except KeyboardInterrupt:
    mainScr.tearDown()
    if(cfg.debug):
      cfg.dbgF.close()
  
