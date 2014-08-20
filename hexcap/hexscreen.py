#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import os
import math
import curses
import locale
import sys
import copy

# hexcap specific imports
import cfg
import minibuffer
import capture
import packet
import layer
import section

# Our generic ScreenError exception class
class ScreenError(Exception):
  def __init__(self, msg):
    curses.echo()
    curses.endwin()

# Our wrapper class for an ncurses screen
class HexScreen:

  def __init__(self):
    locale.setlocale(locale.LC_ALL, '')
    self.code = locale.getpreferredencoding()
    self.stdscr = curses.initscr()
    curses.noecho()
    curses.raw()
    self.stdscr.keypad(1)

    self.headerHeight = 2 # Section / Column names
    self.footerHeight = 2 # Includes blank line

    # Our stack of hidden sections
    self.hiddenSectIDs = []

    # Are we in insert mode?
    self.insert = False

    # Packet ID of marked packet. One based.
    # Zero means no marked packet
    self.mark = 0

    # Flag is True if mini-buffer has focus
    self.mBufFocus = False

    # Message to be printed to mBuf for one cycle and then cleared
    self.mBufMsg = ''

  def tearDown(self, dieStr=''):
    self.stdscr.keypad(0)
    curses.echo()
    curses.endwin()
    if(len(dieStr)):
      print(dieStr)
    sys.exit(0)

  # Initializes our ncurses pad
  # Takes a Capture object
  def initPad(self, cap):
    self.cap = cap
    self.maxY, self.maxX = self.stdscr.getmaxyx()
    self.ppadTopY = self.headerHeight # Topmost ppad position on screen
    self.ppadBottomY = self.maxY - self.footerHeight # Bottommost ppad position on screen
    self.ppadRows = len(self.cap.packets) # Total number of lines in ppad 
    self.buildSections()
    self.drawPpads()
    self.initCursor()
    self.refresh()

  # Initialize all cursor attributes
  def initCursor(self):
    self.cY = self.headerHeight
    self.cX = self.offLimitsWidth
    self.ppadCurY = 0 # Current topmost visible Y in ppad
    self.ppadCurX = 0 # Current leftmost visible X in ppad

  # Completely redraws our ppad and rebuilds our section list
  # Sets ppadWidth
  def drawPpads(self):
    if(self.ppadRows != len(self.cap.packets)): # Our capture has changed in size
      self.buildSections()

    # Draw our packet ppad
    self.ppadRows = len(self.cap.packets)
    self.ppadWidth = self.tableWidth + 1 # Don't understand, why the extra 1?
    self.ppad = curses.newpad(self.ppadRows, self.ppadWidth)
    self.stdscr.clear()
    self.ppad.clear()
    y = 0
    for p in self.cap.packets:
      self.drawPktLine(y, p.out())
      y += 1

    # Create our header ppad
    self.headPpad = curses.newpad(2, self.ppadWidth)

  def refresh(self):
    #    cfg.dbg("hexscreen.py refresh tw:" + str(self.tableWidth) + " ppadCurX:" + str(self.ppadCurX) + " maxX:" + str(self.maxX))
    if(curses.is_term_resized(self.maxY, self.maxX)):
      cfg.dbg("Caught resize event. Consider using immedok()")
      self.tearDown()

    self.drawHeader()
    self.drawFooter()

    # Handle the mini-buffer
    if(self.mBufFocus):
      eStr = self.mBuf.exe()
      if(eStr):
        self.toggleMBuf()
        self.stdscr.move(self.cY, self.cX)
        self.genericTry(eStr)
      else:
        self.printToMBuf(self.mBuf.out())
        self.stdscr.move(self.maxY - 1, self.mBuf.cX)
    else:
      self.printToMBuf(self.mBufMsg)
      self.mBufMsg = ''
      self.stdscr.move(self.cY, self.cX)

    self.refreshBoldPacket()
    self.headPpad.refresh(0, self.ppadCurX, 0, 0, self.headerHeight, self.maxX - 1)
    self.ppad.refresh(self.ppadCurY, self.ppadCurX, self.ppadTopY, 0, self.ppadBottomY, self.maxX - 1)
    self.stdscr.refresh()
    curses.doupdate()

  # Determines the correct order of sections to display based on capture
  def buildSections(self):
    # Remember which sections are exposed before clobbering self.sections
    hiddenSections = []
    if(hasattr(self, 'sections')):
      for s in self.sections:
        if(not s.exposed):
          hiddenSections.append(s.ID)

    self.sections = []
    IDs = [] # Holds temp list of sections we've added to self.sections
    for pkt in self.cap.packets:
      for lay in pkt.layers:
        if(not(lay.ID in IDs)):
          IDs.append(lay.ID)

          # Construct our new section
          s = section.Section(lay.ID, lay.position)
          for col,width in lay.cols.iteritems():
            s.append(col, width)
          # non-default values for layers need to be handled here
          if(s.ID in hiddenSections): 
            s.exposed = False
          else:
            s.exposed = lay.exposed
          s.exposable = lay.exposable
          s.RO = lay.RO

          # append/insert our new section
          if(len(self.sections) <= 1):
            self.sections.append(s)
          else:
            for ii in xrange(len(self.sections)):
              if(ii == len(self.sections) - 1):
                self.sections.append(s)
                break
              elif(s.position <= self.sections[ii].position):
                self.sections.insert(ii, s)
                break

  # Relative Y cursor position in our ppad
  def _get_ppadCY(self):
    return self.ppadCurY + self.cY - self.ppadTopY
  ppadCY = property(_get_ppadCY)

  # Relative X cursor position in our ppad
  def _get_ppadCX(self):
    return self.ppadCurX + self.cX
  ppadCX = property(_get_ppadCX)

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
    return max(1, rv)
  tableWidth = property(_get_tableWidth)

 # Leftmost width that is off limits to cursor
  def _get_offLimitsWidth(self):
    rv = 0
    for s in self.displayedSections:
      if(s.RO):
        rv += s.width
      else:
        return rv
    return False
  offLimitsWidth = property(_get_offLimitsWidth)

 # Leftmost sections that are off limits to cursor
  def _get_offLimitsSections(self):
    rv = 0
    for s in self.displayedSections:
      if(s.RO):
        rv += 1
      else:
        return rv
    return rv
  offLimitsSections = property(_get_offLimitsSections)

  # Returns header section that cursor X value is currently in
  # Takes X value of cursor
  def cursorSection(self, x):
    dSections = self.displayedSections
    totX = self.ppadCurX * -1
    for s in dSections:
      if(x < totX + s.width):
        return s
      else:
        totX += s.width
    return dSections.reversed.next()

  # Returns header section and column key that passed X value is currently in
  # Takes X screen position
  def cursorColumn(self, x):
    totX = self.ppadCurX * -1
    for s in self.displayedSections:
      if(x < totX + s.width - 1):
        if(s.exposed):
          for col, cWidth in s.c.iteritems():
            if(x < totX + cWidth):
              return list((s, col))
            else:
              totX += cWidth + 1
        else:
          return list((s, None))
      else:
        totX += s.width

  # Returns leftmost screen X value for passed section name
  def sectionLeft(self, sid):
    rv = self.ppadCurX * -1
    for s in self.displayedSections:
      if(s.ID == sid):
        return rv
      else:
        rv += s.width
    raise ScreenError, "sectionLeft:Section not found"

  # Returns center screen X value for passed section name
  def sectionCenter(self, sid):
    rv = self.ppadCurX * -1
    for s in self.displayedSections:
      if(s.ID == sid):
        c = rv + (int(math.floor(s.width / 2)))
        return c
      else:
        rv += s.width
    raise ScreenError, "sectionCenter:Section not found"

  # Returns leftmost screen X value(after "|") for passed section and column name
  # If column is None then returns leftmost screen X value(after "|") for section only
  def columnLeft(self, sid, cid=None):
    rv = self.sectionLeft(sid)
    if(cid == None):
      return rv

    for s in self.displayedSections:
      if(s.ID == sid):
        if(s.exposed):
          for col, width in s.c.iteritems():
            if(col == cid):
              return rv
            else:
              rv += width + 1
        else:
          return rv
    raise ScreenError, "columnLeft:Column not found"

  # Returns rightmost screen X value(before "|") for passed section and column name
  def columnRight(self, sid, cid):
    for s in self.displayedSections:
      if(s.ID == sid):
        if(s.exposed):
          return self.columnLeft(sid, cid) + s.c[cid] - 1
        else:
          return self.sectionLeft(sid) + s.width - 1

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
  # cfg.dbg("drawPktLine y:" + str(y) + " pid:" + str(row['pid']['pid']) + " bold:" + str(bold) + " rev:" + str(reverse))
  def drawPktLine(self, y, row, bold=False, reverse=False):
    x = 0
    for s in self.sections:
      if(s.visible):
        if(s.exposed):
          if(s.ID in row):
            for colName, width in s.c.iteritems():
              if(reverse):
                self.ppadAddStr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_REVERSE)
              else:
                if(bold):
                  self.ppadAddStr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_BOLD)
                else:
                  self.ppadAddStr(y, x, row[s.ID][colName].rjust(width) + "|")
              x += width + 1

          else:
            self.ppadHLine(y, x, " ", s.width - 1)
            self.ppadAddStr(y, x + s.width - 1, "|")
            x += s.width
        else:
          self.ppadHLine(y, x, "-", s.width - 1)
          self.ppadAddStr(y, x + s.width - 1, "|")
          x += s.width
      else:
        continue

  # Draws our top 2 header rows
  def drawHeader(self):
    x0 = 0
    x1 = 0
    for s in self.sections:
      if(s.visible):
        if(s.exposed):
          head = "{" + s.ID + "}"
          head = head.center(s.width - 1, " ") + "|"

          self.headPpadAddStr(0, x0, head)
          x0 += s.width
          for column, width in s.c.iteritems():
            col = column.center(width, " ")
            self.headPpadAddStr(1, x1, col + "|", curses.A_REVERSE)
            x1 += width + 1

        else:
          head = "{" + s.ID + "}|"
          self.headPpadAddStr(0, x0, head)
          self.headPpadHLine(1, x1, "-", s.width - 1, curses.A_REVERSE)
          self.headPpadAddStr(1, x1 + s.width - 1, "|", curses.A_REVERSE)
          x0 += s.width
          x1 += s.width
      else:
        continue
        
  # Draws our footer
  def drawFooter(self):
    s,c = self.cursorColumn(self.cX)
    y = self.maxY - self.footerHeight
    x = 0
    divider = 2

    def addElement(sf):
      sf = "[" + sf + "]"
      self.stdscr.hline(y, x, "-", divider)
      self.stdscr.addstr(y, x + divider, sf)
      return divider + len(sf)

    x += addElement(self.cap.fName)

    txt = str(self.ppadCY + 1) + "/" + str(len(self.cap.packets))
    x += addElement(txt)

    if(self.mark):
      txt = "MRK"
    elif(self.insert):
      txt = "INS"
    else:
      txt = "NAV"
    x += addElement(txt)

    if(s.exposed):
      if(s.RO):
        txt = s.ID + "/" + c + "/RO"
      else:
        txt = s.ID + "/" + c + "/RW"
    else:
      txt = s.ID + "/-/-"
    x += addElement(txt)

    if(self.cap.ifName):
      x += addElement(self.cap.ifName)

    # Show generators if present
    if(self.cap.packets[self.ppadCY].hasLayer('g')):
      for lay in self.cap.packets[self.ppadCY].genLayers:
        if(lay.ID == s.ID):
          for col in lay.gen:
            if(col == c):
              txt = "cnt:" + str(lay.gen[col]['count'])
              txt += " stp:" + str(lay.gen[col]['step'])
              txt += " msk:" + lay.gen[col]['mask']
              x += addElement(txt)
              break

    # Claim remaining space
    if(self.tableWidth > x):
      self.stdscr.hline(y, x, "-", self.tableWidth - x)

  # Handles pageUp and pageDown
  def page(self, dY):
    if(self.ppadBottomY >= self.ppadRows):
      return

    self.drawPktLine(self.ppadCY, self.cap.packets[self.ppadCY].out())
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

  # Move cursor to first column after pktID
  def gotoLineBegin(self):
    self.ppadCurX = 0
    self.cX = self.offLimitsWidth

  # Move cursor to end of line
  def gotoLineEnd(self):
    if(self.maxX > self.tableWidth):
      self.cX = self.tableWidth - 2
    else:
      self.ppadCurX = self.tableWidth - self.maxX
      self.cX = self.maxX - 2

  # Moves cursor right and left by delta columns
  def shiftColumn(self, delta):
    dSections = self.displayedSections
    if(len(dSections) < 2):
      return

    if(self.cX >= self.maxX): # Reset our cursor and shift screen if we shifted off screen
      s, col = self.cursorColumn(self.cX)
      if(col == None):
        self.ppadCurX += s.width
      else:
        self.ppadCurX += s.c[col]
      self.cX = self.maxX - 1
    elif(self.cX < 0):
      self.ppadCurX += self.cX
      s, col = self.cursorColumn(1)
      self.cX = self.columnRight(s.ID, col)

    if(delta == 0): # Where every call to this function usually ends up
      return

    sect, col = self.cursorColumn(self.cX)
    if(col == None):
      ii = -1
      for s in dSections:
        ii += 1
        if(s.ID == sect.ID): # Found sect
          if(delta > 0):
            if(ii == len(dSections) - 1):
              return
            else:
              ns = dSections[ii + 1]
              self.cX = self.columnLeft(ns.ID, None)
              self.shiftColumn(delta - 1)
          else:
            if(ii <= self.offLimitsSections): # Leftmost RO sections are off limits
              return
            else:
              ns = dSections[ii - 1]
              self.cX = self.columnLeft(ns.ID, None)
              self.shiftColumn(delta + 1)

    else:
      sii = -1
      for s in dSections:
        sii += 1
        if(sect.ID == s.ID):
          cii = -1
          for c,w in s.c.iteritems():
            cii += 1
            if(c == col): # Found sect and col
              if(delta > 0):
                if(cii == len(s.c) - 1): # Last column
                  if(sii == len(dSections) - 1): # Last section and column
                    return
                  else:
                    ns = dSections[sii + 1]
                    nc = ns.c.getStrKey(0)
                    self.cX = self.columnLeft(ns.ID, nc)
                    self.shiftColumn(delta - 1)
                else:
                  self.cX = self.columnLeft(s.ID, s.c.getStrKey(cii + 1))
                  self.shiftColumn(delta - 1)
              else:
                if(cii == 0):
                  if(sii <= self.offLimitsSections): # Leftmost RO sections are off limits
                    return
                  else:
                    ns = dSections[sii - 1]
                    nc = ns.c.getStrKey(len(ns.c) - 1)
                    self.cX = self.columnLeft(ns.ID, nc)
                    self.shiftColumn(delta + 1)
                else:
                  self.cX = self.columnLeft(s.ID, s.c.getStrKey(cii -1))
                  self.shiftColumn(delta + 1)

  # Moves our cursor, takes deltaY and deltaX
  # Either deltaY or deltaX MUST be 0
  def move(self, dY, dX):
    #    cfg.dbg("move cX:" + str(self.cX) + " dY:" + str(dY) + " dX:" + str(dX) + " ppadCurX:" + str(self.ppadCurX))

    # Finds the next valid X position for cursor
    # Returns False if no such position exists
    def findValidX(diffX):
      if((self.ppadCX + diffX >= self.ppadWidth - 1) or (self.ppadCX + diffX < self.offLimitsWidth)):
        return False
      else:
        validChars = copy.deepcopy(cfg.hexChars)
        validChars.append(ord('-')) # For hidden sections
        validChars.append(ord('.')) # For the undefined layer
        if(ord(self.inch(self.ppadCY, self.ppadCX + diffX)[1]) in validChars):
          return diffX
        else:
          if(diffX > 0):
            return findValidX(diffX + 1)
          else:
            return findValidX(diffX - 1)

    if(dY == 0 and dX == 0):
      return

    if(dY != 0):
      if(dY > 0):
        if(self.cY + 1 < self.ppadBottomY): # Are we not at the bottom of the screen
          if(self.ppadCY + 1 < len(self.cap.packets)): # Are we not at the end of the ppad
            self.cY += 1
        else:
          if(self.ppadCurY + self.ppadBottomY - self.ppadTopY < self.ppadRows):
            self.ppadCurY += 1
      else:
        if(self.cY - 1 >= self.ppadTopY):
          self.cY -= 1
          self.move(dY+1 ,0)
        elif(self.cY - 1 == self.ppadTopY - 1):
          if(self.ppadCurY > 0):
            self.ppadCurY -= 1

    elif(dX != 0):
      if(dX > 0):
        vX = findValidX(1)
        if(not vX):
          return
        if(self.cX + vX < self.tableWidth - self.ppadCurX):
          if(self.cX + vX < self.maxX):
            self.cX += vX
          else:
            self.ppadCurX += vX
      else:
        vX = findValidX(-1)
        if(not vX):
          return
        if(self.cX + vX > max(0, self.offLimitsWidth - self.ppadCurX - 1)):
          self.cX += vX
        else:
          self.ppadCurX = max(0, self.ppadCurX + vX)

        if(self.ppadCurX > 0 and self.ppadCurX <= self.offLimitsWidth and self.cX <= self.offLimitsWidth): # Reset screen to far left
          self.cX = self.offLimitsWidth
          self.ppadCurX = 0

    if(dY > 0):
      self.move(dY-1, 0)
    elif(dY < 0):
      self.move(dY+1, 0)
    elif(dX > 0):
      self.move(0, dX-1)
    elif(dX < 0):
      self.move(0, dX+1)

  def toggleExpose(self, s=None):
    if(not s):
      s = self.cursorSection(self.cX)

    if(not s.exposable):
      return

    if(s.exposed):
      s.exposed = False
    else:
      s.exposed = True
      self.cX = self.sectionCenter(s.ID)

    self.drawPpads()
    self.resetCursor()
    self.refresh()

  # Either expose all sections or unexpose all sections, whichever will toggle more sections
  def toggleExposeAll(self):
    x = 0
    for s in self.sections:
      if(s.exposed):
        x += 1
      else:
        x -= 1

    if(x > int(math.floor(len(self.sections) / 2))):
      expose = False
    else:
      expose = True
    for s in self.sections:
      if(expose != s.exposed):
        self.toggleExpose(s)

  def toggleInsert(self):
    if(self.mark): # Cannot enter insert mode with mark set
      return

    if(self.insert):
      self.insert = False
    else:
      self.insert = True

  def toggleMBuf(self):
    if(self.mBufFocus):
      self.mBufFocus = False
      self.printToMBuf()
      del self.mBuf
    else:
      self.mBuf = minibuffer.MiniBuffer()
      self.mBufFocus = True

  # Prints text to the mini-buffer
  def printToMBuf(self, s=''):
    if(len(s.strip()) > 0):
      self.stdscr.addstr(self.maxY - 1, 0, s.strip()[:self.maxX])
      self.stdscr.hline(self.maxY - 1, len(s.strip()), " ", self.maxX)
    else:
      self.stdscr.hline(self.maxY - 1, 0, " ", self.maxX)

  # Handles all character input to mBuf
  def inputToMBuf(self, c):
    if(curses.keyname(c) == '^Q' or curses.keyname(c) == '^X' or curses.keyname(c) == '^['):
      self.toggleMBuf()
    else:
      self.mBuf.input(c)

  def getch(self):
    return self.stdscr.getch()

  # Takes ppad relative y,x coordinates
  # Returns list((int)attributes, (chr)character) at that location on our ppad
  def inch(self, y, x):
    # curses.inch() returns 3 bytes; left byte is attributes, right 2 bytes are the character
    inpt = hex(self.ppad.inch(y, x))[2:].zfill(6) 
    return list((int(inpt[:2], 16), chr(int(inpt[2:], 16))))

  # Executes passed string in try/except
  # Properly exits if exception raised
  def genericTry(self, s):
    try:
      rv = eval(s)
      if(rv):
        self.printToMBuf(rv)
    except:
      curses.echo()
      curses.endwin()
      raise

  # Transmits packets by calling capture.tx()
  # Handles blocking/unblocking and keyboard Interrupt from user
  # If repeat is zero then loop until broken by user
  def tx(self, first, last, repeat):
    def end(): # Called before we return
      self.stdscr.nodelay(0) # Reblock character input
      if(fail):
        self.printToMBuf("Error:One or more packets failed to transmit")
      else:
        self.printToMBuf(str(pktSent) + " packets egressed " + self.cap.ifName)

    if(os.getuid() or os.geteuid()):
      return "Error:Requires root access"

    pkts = []
    fail = False
    pktSent = 0

    # Convert from user's 1-based numbering to internal 0-based numbering
    first -= 1
    last -= 1

    if(first <= last): # User wants normal ordering
      if(first < 0):
        first = 0
      if(last > len(self.cap.packets) - 1):
        last =  len(self.cap.packets) - 1
      for jj in xrange(first, last+1):
        pkts.append(jj)

    else: # User wants reverse ordering
      if(last < 0):
        last = 0
      if(first > len(self.cap.packets) - 1):
        first =  len(self.cap.packets) - 1
      for jj in xrange(first, last-1, -1):
        pkts.append(jj)

    self.printToMBuf("Any key to break")
    self.stdscr.nodelay(1) # Unblock character input
    if(repeat == 0):
      while True:
        for jj in pkts:
          rv = self.cap.tx(self.cap.packets[jj])
          if(rv):
            pktSent += rv
          else:
            fail = True

          if(self.getch() != -1):
            end()
            return

    else:
      for ii in xrange(repeat):
        for jj in pkts:
          rv = self.cap.tx(self.cap.packets[jj])
          if(rv):
            pktSent += rv
          else:
            fail = True

          if(self.getch() != -1):
            end()
            return
    end()

  # Receives packets by calling capture.rx()
  # Handles blocking/unblocking and keyboard Interrupt from user
  # Redraws ppad after some captured packets
  # Takes count of packets to capture, and BPF filter
  # BPF filter can be NULL
  def rx(self, count, *filt):
    def end(): # Called before we return
      self.stdscr.nodelay(0) # Reblock character input
      self.initPad(self.cap)
      self.refresh()

    def redraw(): # Called when we need to refresh during capture
      self.initPad(self.cap)
      self.refresh()
      self.printToMBuf("Any key to break")

    if(filt):
      rv = self.cap.initRx(filt[0])
      if(rv != None):
        self.printToMBuf(rv)
        return
    elif(len(filt) == 0):
      rv = self.cap.initRx('')
      if(rv != None):
        self.printToMBuf(rv)
        return
    else:
      cfg.dbg("Error in hexscreen.rx(): Bad filter")
      return

    self.printToMBuf("Any key to break")
    self.stdscr.nodelay(1) # Unblock character input
    captured = 0
    if(count == 0):
      while True:
        rv = self.cap.rx()
        if(rv != 0): # We got a packet
          captured += rv
          if((captured % 10) == 0):
            redraw()

        if(self.getch() != -1):
          end()
          return

    else:
      while(captured != count):
        rv = self.cap.rx()
        if(rv != 0): # We got a packet
          captured += rv
          if((captured % 5) == 0):
            redraw()

        if(self.getch() != -1):
          end()
          return

    end()

  # Mini-buffer function for modifying a column
  # Takes a command string and variable list of args
  def modCol(self, f, *args):
    def redraw(): # Redraws screen after modifying column
      self.buildSections()
      self.resetCursor()
      self.drawPpads()
      self.refresh()
        
    s, cid = self.cursorColumn(self.cX)
    sid = s.ID
    if(not s.exposed):
      self.printToMBuf("Error:Cannot modify hidden section")
      return
    if(s.RO):
      self.printToMBuf("Error:Layer is read only")
      return
    if(not self.cap.packets[self.ppadCY].hasLayer(sid)):
      self.printToMBuf("Error:Internal")
      return
    
    if(f == 'generator'):
      if(len(args) != 2):
        self.printToMBuf("Error:Internal")
        return
      else:
        count = args[0]
        step = args[1]

      rv = self.cap.packets[self.ppadCY].addGenerator(sid, cid, count, step)
      if(rv):
        self.printToMBuf(rv)
        return
      else:
        redraw()

    elif(f == 'mask'):
      if(len(args) != 1):
        self.printToMBuf("Error:Internal")
        return
      else:
        mask = args[0]

      if(len(mask) < 1):
        self.printToMBuf("Error:Mask too short")
        return

      # Mask can only contain hexChars
      mask = mask.translate(None, '.,:').strip().lower()
      if(len(mask.translate(None, ''.join(map(chr, cfg.hexChars)))) != 0):
        self.printToMBuf("Error:Mask may only contain hex digits")
        return

      # binMask must contain at least 1 zero
      # binMask cannot have more than one grouping of zeros    
      # Valid masks: 110011, 1, 1100, 0011, 10
      # Invalid masks: 00101, 110010, 0101
      binMask = cfg.hexStrToBinStr(mask)
      if(binMask.find('0') == -1):
        self.printToMBuf("Error:Invalid mask")
        return
      if(binMask.startswith('0')):
        if(binMask.lstrip('0').find('0') != -1):
          self.printToMBuf("Error:Invalid mask")
          return
      else:
        if(binMask.lstrip('1').lstrip('0').find('0') != -1):
          self.printToMBuf("Error:Invalid mask")
          return

      self.cap.packets[self.ppadCY].addMask(sid, cid, binMask)
      redraw()

  # Wrapper for ppad.addstr
  def ppadAddStr(self, y, x, s, atr=None):
    if(atr):
      self.genericTry("self.ppad.addstr(" + str(y) + "," + str(x) + ",'" + s + "'," + str(atr) + ")")
    else:
      self.genericTry("self.ppad.addstr(" + str(y) + "," + str(x) + ",'" + s + "')")

  # Wrapper for ppad.hline
  def ppadHLine(self, y, x, char, width, atr=None):
    if(atr):
      self.genericTry("self.ppad.hline(" + str(y) + "," + str(x) + ",'" + char + "'," + str(width) + "," + str(atr) + ")")
    else:
      self.genericTry("self.ppad.hline(" + str(y) + "," + str(x) + ",'" + char + "'," + str(width) + ")")

  # Wrapper for header ppad.addstr
  def headPpadAddStr(self, y, x, s, atr=None):
    if(atr):
      self.genericTry("self.headPpad.addstr(" + str(y) + "," + str(x) + ",'" + s + "'," + str(atr) + ")")
    else:
      self.genericTry("self.headPpad.addstr(" + str(y) + "," + str(x) + ",'" + s + "')")

  # Wrapper for ppad.hline
  def headPpadHLine(self, y, x, char, width, atr=None):
    if(atr):
      self.genericTry("self.headPpad.hline(" + str(y) + "," + str(x) + ",'" + char + "'," + str(width) + "," + str(atr) + ")")
    else:
      self.genericTry("self.headPpad.hline(" + str(y) + "," + str(x) + ",'" + char + "'," + str(width) + ",)")

  # Handles our character insertion
  # Modifies column then increments cursor X position by 1
  def handleInsert(self, c):
    sect,col = self.cursorColumn(self.cX) 
    if(sect.RO): # Cursor section ReadOnly
      return
    elif(not sect.exposed): # Cursor section not exposed
      return
    elif(not self.cap.packets[self.ppadCY].hasLayer(sect.ID)): # Cursor section not in packet
      return

    attr,char = self.inch(self.ppadCY, self.ppadCX)
    if(ord(char) not in cfg.hexChars): # Cursor character is immutable
      self.move(0, 1)
      return

    leftX = self.columnLeft(sect.ID, col)
    rightX = self.columnRight(sect.ID, col)

    val = ""
    for x in xrange(leftX, rightX + 1):
      if(x == self.cX):
        val += chr(c)
      else:
        attr,char = self.inch(self.ppadCY, self.ppadCurX + x)
        val += char

    self.cap.packets[self.ppadCY].setColumn(sect.ID, col, val)
    self.move(0, 1)

  def toggleMark(self):
    if(self.insert): # Cannot set mark in insert mode
      return

    if(self.mark):
      self.mark = 0
      self.drawPpads()
      self.refresh()
    else:
      self.mark = self.ppadCY + 1

  # Called after an action MAY cause cY,cX,ppadCurY,ppadCurX to be in illegal position(s)
  # Returns them to legal position(s)
  def resetCursor(self):
    # Handle X
    if(self.ppadCurX >= self.tableWidth - self.maxX):
      self.ppadCurX = self.tableWidth - self.maxX - 2
    self.ppadCurX = max(0, self.ppadCurX)

    # Too far right
    if(self.cX > self.maxX - 1):
      self.cX = self.maxX - 1
    elif(self.cX > self.tableWidth - self.ppadCurX - 2):
      self.cX = self.tableWidth - self.ppadCurX - 2

    # Too far left
    if(self.cX < self.offLimitsWidth - self.ppadCurX):
      self.cX = self.offLimitsWidth

    # Handle Y
    if(self.ppadCurY >= len(self.cap.packets) - self.maxY):
      self.ppadCurY = len(self.cap.packets) - self.maxY - 1
    self.ppadCurY = max(0, self.ppadCurY)

    if(len(self.cap.packets) <= 1):
      self.cY = self.ppadTopY

    elif(self.cY < self.ppadTopY):
      self.cY = self.ppadTopY

    elif(self.cY > self.ppadBottomY):
      self.cY = self.ppadBottomY

    elif(self.ppadCY >= len(self.cap.packets)):
      self.cY = self.ppadTopY + len(self.cap.packets) - 1

    # Actually move the cursor
    self.stdscr.move(self.cY, self.cX)

  #    cfg.dbg("Hexscreen_yank len_packets:" + str(len(self.cap.packets)) + " len_clipboard:" + str(len(self.cap.clipboard)) + \
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
    self.drawPpads()
    self.refresh()

  # Yanks a single packet to clipboard
  def yankPacket(self):
    if(not (len(self.cap.packets) > 1)):
      return

    self.cap.yank(self.ppadCY, self.ppadCY)    
    self.resetCursor()
    self.drawPpads()
    self.refresh()

  def paste(self):
    if(len(self.cap.clipboard) == 0):
      return

    self.cap.paste(self.ppadCY)
    self.cY += len(self.cap.clipboard)
    self.resetCursor()
    self.drawPpads()
    self.refresh()
