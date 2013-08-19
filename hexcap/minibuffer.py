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

import curses
import cfg

# Implements a simple Emacs style mini-buffer
class MiniBuffer:

  def __init__(self):
    # Actual MiniBuffer buffer
    self.mBuf = ''

    # Our X cursor position
    self.cX = 0

    # Message to print to mini-buffer instead of mBufMsg
    # Takes the form list((displayCycles), (msg))
    # Where displayCycles is how many curses refresh cycles you want it to display for(zero-based positive integer)
    self.mBufMsg = []

  def __del__(self):
    pass

  # Returns string to be printed to minibuffer
  def out(self):
    cfg.dbg("drawMiniBuffer len_mBufMsg:" + str(len(self.mBufMsg)) + " mBuf:" + self.mBuf)
    if(len(self.mBufMsg) > 0):
      if(self.mBufMsg[0][0] < 1):
        return self.mBufMsg.pop(0)[1]
      else:
        self.mBufMsg[0][0] -= 1
        return self.mBufMsg[0][1]
    else:
      return self.mBuf

  # Inputs character c to self.mBuf
  def input(self, c):
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

  # Clears mini-buffer
  def clear(self):
    self.stdscr.hline(self.maxY - 1, 0, " ", self.maxX)


