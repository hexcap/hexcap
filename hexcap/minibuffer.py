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

  # Allowed mini-buffer characters
  allowedChars = []
  for x in xrange(0, 10): # digits 0-9
    allowedChars.append(ord(str(x)))
  for x in xrange(97, 123): # lowercase alpha
    allowedChars.append(x)
  allowedChars.append(45) # - 'dash'

  # MiniBuffer dispatch table
  # key = command, val = fList
  # Where fList takes the form [function, [argList]]
  # Where argList is a list of 2 string pairs [type, range]
  # Where type can be either s(string) or i(integer)
  # if type=='s' then range is a list of possible strings
  # if type=='i' then range is a range given as 'min-max' inclusive
  # function is eval()'d in the context of parent object
  cmds = {
    'set-pkt-min-size' : ['self.cap._set_minPktSize', [['i', '60-70']]],
    'set-pkt-max-size' : ['self.cap._set_maxPktSize', [['i', '1000-1500']]],
    'set-pkt-size-range' : ['self.cap.setPktSizeRange', [['i', '60-70'], ['i', '1000-1500']]],
    'append-layer' : ['self.cap.appendLayer', [['s', ['funk']]]],
    'insert-layer' : ['self.cap.insertLayer', [['s', ['funk', 'bar']]]],
    'delete-layer' : ['self.cap.deleteLayer', [['s', ['funk', 'foo']]]]
    }
  
  def __init__(self):
    # The function and argument-list to be eval()'d by parent object
    self.func = ''
    self.args = []
    self.resetPrompt()

  def __del__(self):
    pass

  # Resets prompt
  def resetPrompt(self):
    # Actual MiniBuffer buffer
    self.buf = ''

    # Our X cursor position
    self.cX = 0

    # Our prompt when awating arguments
    self.argPrompt = ''

    # Message to return from out() instead of buf
    # Will be printed for 1 cycle then discarded
    self.msg = ''

  # Returns string to be printed to minibuffer
  def out(self):
#    cfg.dbg("mBuf.out len_mBufMsg:" + str(len(self.msg)) + " mBuf:" + self.buf)
    if(len(self.msg) > 0):
      msg = self.msg
      self.msg = ''
      return msg
    else:
      return self.buf

  # Returns string to be eval()'d by parent object
  # Returns False if nothing to execute
  def exe(self):
    if(len(self.func) == 0):
      return False
    elif(len(self.args) == len(self.cmds[self.func][1])):
      rv = self.cmds[self.func][0] + "("
      for a in self.args:
        rv += a + ","
      return rv.rstrip(",") + ")"
    else:
      return False

  # Top-level input
  def input(self, c):
#    cfg.dbg("mBuf.input c:" + str(c) + " cX:" + str(self.cX) + " buf:" + self.buf + " argPrompt:" + self.argPrompt)
    if(curses.keyname(c) == '^?'): # Backspace
      if(len(self.buf) > len(self.argPrompt)):
        self.buf = self.buf[:len(self.buf)-1]
        self.cX -= 1

    elif(c == curses.KEY_RIGHT):
      if(self.cX < len(self.buf)):
        self.cX += 1

    elif(c == curses.KEY_LEFT):
      if(self.cX > 0):
        self.cX -= 1

    elif(curses.keyname(c) == '^A'): # Goto beginning of line
      self.cX = len(self.argPrompt)

    elif(curses.keyname(c) == '^E'): # Goto end of line
      self.cX = len(self.buf)
      
    elif(curses.keyname(c) == '^J' or curses.keyname(c) == '^M' or curses.keyname(c) == '^I'): # Enter/Return/TAB
      if(len(self.argPrompt) > 0):
        self.inputArgs(c)
      else:
        self.inputFunc(c)

    elif(c in self.allowedChars):
      if(self.cX >= len(self.buf)):
        self.buf += chr(c)
      elif(self.cX == 0):
        self.buf = chr(c) + self.buf
      else:
        self.buf = self.buf[:self.cX -1] + chr(c) + self.buf[self.cX:]
      self.cX += 1

  # Handles input until a mini-buffer function is reached
  def inputFunc(self, c):
    if(curses.keyname(c) == '^J' or curses.keyname(c) == '^M'): # Enter/Return \n
      if(self.buf in self.cmds):
        self.func = self.buf
        self.buf += ":"
        self.argPrompt = self.buf
        self.cX = len(self.buf)
      else:
        self.msg = self.buf + "   [Unknown Command]"

    elif(curses.keyname(c) == '^I'): # TAB completion
      opts = []
      for k,v in self.cmds.iteritems():
        if(k.startswith(self.buf)):
          opts.append(k)

      if(len(opts) == 0):
        self.msg = self.buf + "   [Nothing found]"
      elif(len(opts) == 1):
        self.buf = opts.pop()
        self.cX = len(self.buf)
      else:
        ii = -1
        brk = False
        while not brk:
          ii += 1
          c = opts[0][ii]
          for o in opts:
            if(o[ii] != c):
              self.buf = o[:ii]
              self.cX = len(self.buf)
              brk = True

        msg = self.buf + "   ["
        for ii in xrange(len(opts)):
          if(ii == 2):
            msg += opts[ii] + "|..."
            break
          else:
            msg += opts[ii] + "|"
        self.msg = msg.rstrip("|")+ "]"

  # Handles gathering of arguments for chosen function
  def inputArgs(self, c):
    arg = self.buf[len(self.argPrompt):]
    if(len(arg) < 1):
      return

    argDef = self.cmds[self.func][1][len(self.args)]
    if(curses.keyname(c) == '^J' or curses.keyname(c) == '^M'): # Enter/Return \n
      if(argDef[0] == 'i'):
        if(arg.isdigit()):
          rMin, rMax = argDef[1].split("-")
          rMin = int(rMin)
          rMax = int(rMax)
          arg = int(arg)
          if((arg >= rMin) and (arg <= rMax)):
            self.args.append(str(arg))
          else:
            self.msg = self.buf + "   [Out of Range " + str(rMin) + "-" + str(rMax) + "]"

      elif(argDef[0] == 's'):
        if(arg in argDef[1]):
          self.args.append(arg)

    # Are we done collecting args
    if(len(self.args) == len(self.cmds[self.func][1])):
      self.resetPrompt()
    else:
      self.buf = self.argPrompt
      self.cX = len(self.argPrompt)
