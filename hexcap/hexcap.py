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
import time

# hexcap specific imports
import cfg
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
    self.cY = self.headerHeight
    self.cX = cfg.pktIDWidth + 1
    self.cMX = 0 # X cursor position in mini-buffer

    # Our stack of hidden sections
    self.hiddenSectIDs = []

    # Are we in insert mode?
    self.insert = False

    # Packet ID of marked packet. One based.
    self.mark = 0 # Zero means no marked packet

    # Flag is True if mini-buffer has focus
    self.miniBufferFocus = False

    # Actual miniBuffer buffer
    self.mBuf = ''

    # Message to print to mini-buffer instead of mBufMsg
    # Takes the form list((displayCycles), (msg))
    # Where displayCycles is how many curses refresh cycles you want it to display for
    self.mBufMsg = []

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
    self.ppadTopY = self.headerHeight # Topmost ppad position on screen
    self.ppadBottomY = self.maxY - self.footerHeight # Bottommost ppad position on screen
    self.ppadCurY = 0 # Current topmost visible Y in ppad
    self.ppadCurX = 0 # Current leftmost visible X in ppad
    self.ppadRows = len(self.cap.packets) # Total number of lines in ppad 
    self.buildSections()
    self.drawPpad()
    self.refresh()

  # Completely redraws our ppad and rebuilds our section list
  # Sets ppadWidth
  def drawPpad(self):
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
    if(curses.is_term_resized(self.maxY, self.maxX)):
      cfg.dbg("Caught resize event. Consider using immedok()")
      self.tearDown()
    
    self.drawHeader()
    self.headPpad.refresh(0, self.ppadCurX, 0, 0, self.headerHeight, self.maxX - 1)
    self.drawFooter()
    if(self.miniBufferFocus):
      self.drawMiniBuffer()
      self.stdscr.move(self.maxY - 1, self.cMX)
    else:
      self.stdscr.move(self.cY, self.cX)

    self.refreshBoldPacket()
    self.ppad.refresh(self.ppadCurY, self.ppadCurX, self.ppadTopY, 0, self.ppadBottomY, self.maxX - 1)
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
          s = section.Section(lay.ID, lay.position)
          for col,width in lay.cols.iteritems():
            s.append(col, width)
          # non-default values for layers need to be handled here
          s.RO = lay.RO
          s.exposed = lay.exposed
          s.exposable = lay.exposable

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
  #    cfg.dbg("y:" + str(y) + " pid:" + str(row['pid']['pid'])+ " bold:" + str(bold) + " rev:" + str(reverse))
  def drawPktLine(self, y, row, bold=False, reverse=False):
    if("unsupported" in row): # If packet is unsupported we only print the pid and tstamp
      msg = ''
      decr = 0
      if(self.sections[0].exposed):
        msg += row['pid']['pid'] + "|"
        decr += self.sections[0].width
      if(self.sections[1].exposed):
        msg += row['tstamp']['tstamp'] + "|" 
        decr += self.sections[1].width

      msg += "<<Unsupported>>".center(self.tableWidth - decr - 1) + "|"
      self.ppad.addstr(y, 0, msg)
      return

    x = 0
    for s in self.sections:
      if(s.visible):
        if(s.exposed):
          if(s.ID in row):
            for colName, width in s.c.iteritems():
              if(reverse):
                self.ppadAddstr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_REVERSE)
              else:
                if(bold):
                  self.ppadAddstr(y, x, row[s.ID][colName].rjust(width) + "|", curses.A_BOLD)
                else:
                  self.ppadAddstr(y, x, row[s.ID][colName].rjust(width) + "|")
                  
                x += width + 1
          else:
            self.ppadHline(y, x, " ", s.width - 1)
            self.ppadAddstr(y, x + s.width - 1, "|")
            x += s.width
        else:
          self.ppadHline(y, x, "-", s.width - 1)
          self.ppadAddstr(y, x + s.width - 1, "|")
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

          self.headPpadAddstr(0, x0, head)
          x0 += s.width
          for column, width in s.c.iteritems():
            col = column.center(width, " ")
            self.headPpadAddstr(1, x1, col + "|", curses.A_REVERSE)
            x1 += width + 1

        else:
          head = "{" + s.ID + "}|"
          self.headPpadAddstr(0, x0, head)
          self.headPpadHline(1, x1, "-", s.width - 1, curses.A_REVERSE)
          self.headPpadAddstr(1, x1 + s.width - 1, "|", curses.A_REVERSE)
          x0 += s.width
          x1 += s.width
      else:
        continue
        
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

    self.stdscr.addstr(y, x, "[x:" + str(self.cX + self.ppadCurX).rjust(3))
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

#    cfg.dbg("drawFooter cX:" + str(self.cX) + " tw:" + str(self.tableWidth) + " ppadCurX:" + str(self.ppadCurX))
    s,c = self.cursorColumn(self.cX)
    if(s.exposed):
      if(s.RO):
        txt = "[" + s.ID + "/" + c + "/RO]"
      else:
        txt = "[" + s.ID + "/" + c + "/RW]"
    else:
      txt = "[" + s.ID + "/-/-]"
    self.stdscr.addstr(y, x, txt)
    x += len(txt)

    if(self.tableWidth > x):
      self.stdscr.hline(y, x, "-", self.tableWidth - x)

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

  # Move cursor to first column after pktID
  def gotoLineBegin(self):
    self.ppadCurX = 0
    self.cX = cfg.pktIDWidth + 1

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
            if(ii < 2): # pid section is off limits
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
                  if(sii < 2): # pid section is off limits
                    return
                  else:
                    ns = dSections[sii - 1]
                    nc = ns.c.getStrKey(len(ns.c) - 1)
#                    cfg.dbg("shiftColumn ppadCurX:" + str(self.ppadCurX) + " tw:" + str(self.tableWidth) + 
#                            " cX:" + str(self.cX) + " ns.ID:" + ns.ID + " nc:" + nc)
                    self.cX = self.columnLeft(ns.ID, nc)
                    self.shiftColumn(delta + 1)
                else:
                  self.cX = self.columnLeft(s.ID, s.c.getStrKey(cii -1))
                  self.shiftColumn(delta + 1)

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
        if(self.cX + dX < self.tableWidth - self.ppadCurX - 1):
          if(self.cX + dX < self.maxX):
            self.cX += dX
          else:
            self.ppadCurX += dX
        else:
          if(self.cX + dX == self.tableWidth - self.ppadCurX - 1):
            if(self.cX + dX == self.maxX):
              self.ppadCurX += 1
              self.cX -= dX
      else:
        if(self.cX + dX > cfg.pktIDWidth):
          self.cX += dX
        else:
          if(self.cX + dX > self.ppadCurX * -1):
            self.ppadCurX -= 1

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

    self.drawPpad()
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

  # mini-buffer functions
  # mini-buffer refers to the screen location and user space
  # mBuf refers to the actual mini-buffer buffer
  def toggleMiniBufferFocus(self):
    if(self.miniBufferFocus):
      self.miniBufferFocus = False
      self.mBuf = ''
      self.clearMiniBuffer()
    else:
      self.miniBufferFocus = True

  def drawMiniBuffer(self):
    cfg.dbg("drawMiniBuffer len_mBufMsg:" + str(len(self.mBufMsg)) + " mBuf:" + self.mBuf)
    self.clearMiniBuffer()
    if(len(self.mBufMsg) > 0):
      if(self.mBufMsg[0][0] == 0):
        self.mBufMsg.pop(0)
      else:
        self.mBufMsg[0][0] -= 1
        self.printToMiniBuffer(self.mBufMsg[0][1])
        return

    self.printToMiniBuffer(self.mBuf)

  # Inputs character c to self.mBuf
  def mBufInput(self, c):
    cfg.dbg("mBufInput c:" + str(c) + " cMX:" + str(self.cMX) + " mBuf:" + self.mBuf)

    if(curses.keyname(c) == '^?'): # Backspace
      if(len(self.mBuf) > 0):
        self.mBuf = self.mBuf[:len(self.mBuf)-1]
        self.cMX -= 1

    elif(c == curses.KEY_RIGHT):
      if(self.cMX < len(self.mBuf)):
        self.cMX += 1

    elif(c == curses.KEY_LEFT):
      if(self.cMX > 0):
        self.cMX -= 1

    elif(curses.keyname(c) == '^J' or curses.keyname(c) == '^M'): # Enter/Return \n
      if(self.mBuf in cfg.mBufCmds):
        self.mBuf = ''
        eval(cfg.mBufCmds[self.mBuf])
      else:
        self.mBufMsg.append(list(((1), (self.mBuf + "   [Unknown Command]"))))

    elif(curses.keyname(c) == '^I'): # TAB
      opts = []
      for k,v in cfg.mBufCmds.iteritems():
        if(k.startswith(self.mBuf)):
          opts.append(k)

      if(len(opts) == 0):
        self.mBufMsg.append(list(((1), (self.mBuf + "   [Nothing found]"))))
      elif(len(opts) == 1):
        self.mBuf = opts[0]
        self.cMX = len(self.mBuf)
      else:
        msg = self.mBuf + "   ["
        for ii in xrange(len(opts)):
          if(ii == 2):
            msg += opts[ii] + "|..."
            break
          else:
            msg += opts[ii] + "|"

        self.mBufMsg.append(list(((1), (msg.rstrip("|")+ "]"))))

    elif(c in cfg.mBufChars):
      if(self.cMX >= len(self.mBuf)):
        self.mBuf += chr(c)
      elif(self.cMX == 0):
        return
      else:
        self.mBuf = self.mBuf[:self.cMX -1] + chr(c) + self.mBuf[self.cMX:]
      self.cMX += 1

  # Sets a prompt(PS) at mini-buffer and awaits input, returns once Enter is pressed or is escaped
  def promptMiniBuffer(self, PS):
    self.mBuf = PS
    self.cMX = len(PS)
    while True:
      self.printToMiniBuffer(self.mBuf)
      c = self.getch()
      cfg.dbg("Prompt KeyPress c:" + repr(c) + " ctrl:" + repr(curses.keyname(c)))

      if(c != -1):
        if(curses.keyname(c) == '^X' or curses.keyname(c) == '^['): # Remove mini-buffer focus
          self.toggleMiniBufferFocus()
          return
        elif(curses.keyname(c) == '^?'): # Backspace
          if(len(self.mBuf) > len(PS)):
            self.mBuf = self.mBuf[:len(self.mBuf)-1]
            self.cMX -= 1

        elif(c == curses.KEY_RIGHT):
          if(self.cMX < len(self.mBuf)):
            self.cMX += 1

        elif(c == curses.KEY_LEFT):
          if(self.cMX > len(PS)):
            self.cMX -= 1

        elif(curses.keyname(c) == '^J' or curses.keyname(c) == '^M'): # Enter/Return \n
          self.mBuf = ''
          return self.mBuf[len(PS):].strip()

        elif(c in cfg.mBufChars):
          if(self.cMX >= len(self.mBuf)):
            self.mBuf += chr(c)
          else:
            self.mBuf = self.mBuf[:self.cMX -1] + chr(c) + self.mBuf[self.cMX:]
          self.cMX += 1


  # Prints text to the mini-buffer 
  def printToMiniBuffer(self, s):
    self.stdscr.addstr(self.maxY - 1, 0, s.strip()[:self.maxX])
    
  # Clears mini-buffer
  def clearMiniBuffer(self):
    self.stdscr.hline(self.maxY - 1, 0, " ", self.maxX)

  def getch(self):
    return self.stdscr.getch()

  # Takes ppad relative y,x coordinates
  # Returns list((int)attributes, (chr)character) at that location on our ppad
  def inch(self, y, x):
    inpt = hex(self.ppad.inch(y, x))
    return list((int(inpt[2:4], 16), chr(int(inpt[4:], 16))))

  # TODO: Change these to high order functions
  # Wrapper for packet ppad.addstr with exception handling
  def ppadAddstr(self, y, x, s, atr=None):
    try:
      if(atr):
        self.ppad.addstr(y, x, s, atr)
      else:
        self.ppad.addstr(y, x, s)
    except:
      curses.echo()
      curses.endwin()
      raise

  # Wrapper for packet ppad.hline with exception handling
  def ppadHline(self, y, x, char, width, atr=None):
    try:
      if(atr):
        self.ppad.hline(y, x, char, width, atr)
      else:
        self.ppad.hline(y, x, char, width)
    except:
      curses.echo()
      curses.endwin()
      raise

  # Wrapper for header ppad.addstr with exception handling
  def headPpadAddstr(self, y, x, s, atr=None):
    try:
      if(atr):
        self.headPpad.addstr(y, x, s, atr)
      else:
        self.headPpad.addstr(y, x, s)
    except:
      curses.echo()
      curses.endwin()
      raise

  # Wrapper for ppad.hline with exception handling
  def headPpadHline(self, y, x, char, width, atr=None):
    try:
      if(atr):
        self.headPpad.hline(y, x, char, width, atr)
      else:
        self.headPpad.hline(y, x, char, width)
    except:
      curses.echo()
      curses.endwin()
      raise

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
    if(self.cX > self.maxX - 1):
      self.cX = self.maxX - 1
    elif(self.cX > self.tableWidth - self.ppadCurX - 2):
      self.cX = self.tableWidth - self.ppadCurX - 2
    elif(self.cX < 0):
      self.cX = 0

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

  '''
  DEPRECATED
  def hideSection(self):
    if(len(self.displayedSections) > 1):
      s = self.cursorSection(self.cX)
      s.visible = False
      s.exposed = False
      self.hiddenSectIDs.append(s.ID)
      self.drawPpad()
      self.cX = min(self.cX, self.tableWidth - 2)
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
  '''

###########################
# BEGIN PROGRAM EXECUTION #
###########################

def usage(s):
  print "FATAL ERROR: " + s
  print ""
  print "USAGE: " + sys.argv[0] + " FILE"
  print "FILE must be a valid pcap file"
  sys.exit(1)

# Is inter-key time gap greater than repeatKey
# Resets typeMaticStamp
def checkRepeatKey():
  global repeatKeyStamp
  if(repeatKeyStamp > int(round(time.time() * 100)) - repeatKeyDelay):
    repeatKeyStamp = int(round(time.time() * 100))
    return True
  else:
    repeatKeyStamp = int(round(time.time() * 100))
    return False

cfg.dbg('Start')
# Used for checking for repeat keys
repeatKeyStamp = int(round(time.time() * 100))
repeatKeyDelay = 40 # In hundreths of a second

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
    cfg.dbg("KeyPress c:" + repr(c) + " ctrl:" + repr(curses.keyname(c)))

    if(c != -1):
      if(mainScr.miniBufferFocus):
        if(curses.keyname(c) == '^X' or curses.keyname(c) == '^['): # Toggle miniBuffer focus
          mainScr.toggleMiniBufferFocus()
        elif(curses.keyname(c) == '^Q'): # Quit
          if(cfg.debug):
            cfg.dbgF.close()
          mainScr.tearDown()
        else:
          mainScr.mBufInput(c)

      else:
        mainScr.clearMiniBuffer()
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

        elif(curses.keyname(c) == '^Z'): # Toggle Expose
          if(checkRepeatKey()):
            mainScr.toggleExposeAll()
          else:
            mainScr.toggleExpose()

        elif(curses.keyname(c) == '^F'): # Page Down
          mainScr.page(10)

        elif(curses.keyname(c) == '^B'): # Page Up
          mainScr.page(-10)

        elif(curses.keyname(c) == '^A'): # Goto beginning of line
          mainScr.gotoLineBegin()

        elif(curses.keyname(c) == '^E'): # Goto end of line
          mainScr.gotoLineEnd()

        elif(curses.keyname(c) == '^S'): # Save file
          pc.write(open('garbage.pcap', 'wb'))

          '''
          if(pc.RW):
            writeError = False
            try:
              pass
              f = open(pc.fName, 'wb')
            except:
              writeError = True
              mainScr.printToMiniBuffer("ERROR: Unable to open file for writing >> " + pc.fName)

            if(not writeError):
              writeError = False
              pc.write(f)
              f.close()
          else:
            mainScr.printToMiniBuffer("ERROR: Not all packets supported for read/write")
          '''

        elif(curses.keyname(c) == '<'): # Shift left 1 column
          mainScr.shiftColumn(-1)

        elif(curses.keyname(c) == '>'): # Shift right 1 column
          mainScr.shiftColumn(1)

        elif(curses.keyname(c) == '^R'): # Reread packet capture from disk
          readError = False
          try:
            f = open(pc.fName, 'rb')
          except:
            readError = True
            mainScr.printToMiniBuffer("ERROR: Unable to open file for reading >> " + pc.fName)

          if(not readError):
            readError = False
            pc = capture.Capture(f, pc.fName)
            f.close()
            mainScr.initPad(pc)

        elif(curses.keyname(c) == '^X'): # Toggle miniBuffer focus
          mainScr.toggleMiniBufferFocus()
            
        elif(curses.keyname(c) == '^N'): # Toggle INS/NAV mode
          mainScr.toggleInsert()

        elif(curses.keyname(c) == '^@'): # Set new mark (^@ == 'CTRL-SPACE')
          mainScr.toggleMark()

        elif(curses.keyname(c) == '^Y'): # Paste packet(s)
          mainScr.paste()

        elif(curses.keyname(c) == '^W'): # Yank packets
          mainScr.yank()

        elif(curses.keyname(c) == '^K'): # Yank packet
          mainScr.yankPacket()

        elif(curses.keyname(c) == '^Q' or curses.keyname(c) == 'q'): # Quit
          if(cfg.debug):
            cfg.dbgF.close()
          mainScr.tearDown()

  except KeyboardInterrupt:
    mainScr.tearDown()
    if(cfg.debug):
      cfg.dbgF.close()


# We can't accept the following keys due to possible collisions
# ASCII-decimal  ASCII-character Ctrl-character 
# 8 or 263       BS(Backspace)   H              
# 9              TAB             I
# 10             LF(\n)          M

