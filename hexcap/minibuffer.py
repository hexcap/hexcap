#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import re
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
  allowedChars.append(33) # ! bang
  allowedChars.append(37) # % percent
  allowedChars.append(43) # + plus
  allowedChars.append(45) # - dash
  allowedChars.append(46) # . dot
  allowedChars.append(47) # / forward slash
  allowedChars.append(61) # = equals
  allowedChars.append(64) # @ at
  allowedChars.append(95) # _ underscore

  '''
   MiniBuffer dispatch table
   key = mini-buffer command, val = fList
   flist is eval()'d in the context of parent object
   Where fList takes the form [cmd, [argList]]
   If cmd.endswitch(")") then it is interpreted as a function call
   If cmd.endswitch("=") then it is interpreted as an attribute
   argList is a list of 3 string pairs [type, desc, helpText]
   -Where type can be either s(string) or i(integer)
   --if type=='s' then desc is a regexp that must match
   --if type=='i' then desc is a range given as 'min-max' inclusive
   -Where desc is either regex for 's' OR a range for 'i'
   -Where helpText is optional and shown when inputting, useful when multiple args present

   Do NOT make keys where (keyX.startswith(keyY) == True) for keys keyX and keyY
   '''
  cmds = {
    'pkt-min-size' : ['self.cap._set_minPktSize()', [['i', '60-70']]], # Couldn't get property set to work here
    'pkt-max-size' : ['self.cap._set_maxPktSize()', [['i', '1000-1500']]],
    'pkt-size-range' : ['self.cap.setPktSizeRange()', [['i', '60-70', ' min:'], ['i', '1000-1500', ' max:']]],
    'interface' : ['self.cap.setInterface()', [['s', '^[\w.-_=+,!:%@]*$']]],
    'save-file' : ['self.cap.save()', []],
    'save-as-file' : ['self.cap.saveAs()', [['s', '^[\w.-_=+,!:%@]*$']]],
    'send-all' : ['self.cap.sendRange(1,len(self.cap),)', [['i', '1-999', ' repeat:']]],
    'send-pkt' : ['self.cap.sendRange(self.ppadCY+1,self.ppadCY+1,)', [['i', '1-999', ' repeat:']]],
    'send-range' : ['self.cap.sendRange()', [['i', '1-999', ' first:'], ['i', '1-999', ' last:'], ['i', '1-999', ' repeat:']]]

    #    'append-layer' : ['self.cap.appendLayer()', [['s', '[0-9]2funk']]],
    #    'insert-layer' : ['self.cap.insertLayer()', [['s', '^bar$']]],
    #    'delete-layer' : ['self.cap.deleteLayer()', [['s', 'foo']]]
    }
  
  def __init__(self):
    # The function and argument-list to be eval()'d by parent object
    self.func = ''
    self.args = []
    self.resetPrompt()
    self.tabOptions = 5 # How many options to display with tab completion?

  def __del__(self):
    pass

  # Resets prompt
  def resetPrompt(self):
    # Actual MiniBuffer buffer
    self.buf = ''

    # Our X cursor position
    self.cX = 0

    # The user chosen command from our dispatch table
    self.cmdRef = None

    # Our prompt when awating arguments
    self.argPrompt = ''

    # Message to return from out() instead of buf
    # Will be printed for 1 cycle then discarded
    self.msg = ''

  # Returns string to be printed to minibuffer
  def out(self):
    if(len(self.msg) > 0):
      msg = self.msg
      self.msg = ''
      return msg
    else:
      return self.buf

  # Returns string to be eval()'d by parent object
  # Returns None if nothing to execute
  def exe(self):
    if(len(self.func) == 0):
      return None
    else:
      if(len(self.args) == len(self.cmds[self.func][1])):
        if(len(self.cmds[self.func][1]) == 0):
          return self.cmds[self.func][0]
        else:
          cmd = self.cmds[self.func][0]
          if(cmd.endswith(")")):
            rv = cmd.rstrip(")")
            for a in self.args:
              rv += a + ","
            return rv.rstrip(",") + ")"
          else:
            return cmd + self.args.pop()
      else:
        return None

  # Top-level input
  def input(self, c):
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
        self.cmdRef = self.cmds[self.func][1]
        if(self.cmds[self.buf][1]):
          if(len(self.cmdRef[0]) == 3): # Do we have helpText for our first arg?
            self.buf += self.cmdRef[0][2]
          else:
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

        opts.sort()
        msg = self.buf + "   ["
        for ii in xrange(len(opts)):
          if((ii == self.tabOptions - 1) and (len(opts) > self.tabOptions)):
            msg += opts[ii] + "|..."
            break
          elif(ii == self.tabOptions - 1):
            msg += opts[ii]
            break
          else:
            msg += opts[ii] + "|"
        self.msg = msg.rstrip("|") + "]"

  # Handles gathering of arguments for chosen function
  def inputArgs(self, c):
    arg = self.buf[len(self.argPrompt):]
    if(len(arg) < 1):
      return

    argDef = self.cmdRef[len(self.args)]
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
            return

      elif(argDef[0] == 's'):
        reg = re.compile(argDef[1])
        match = reg.match(arg)
        if(match.span()[1] == len(arg)):
          self.args.append("\'" + str(arg) + "\'")

    # Are we done collecting args
    if(len(self.args) == len(self.cmds[self.func][1])):
      self.resetPrompt()
    else:
      if(len(self.cmdRef[len(self.args)]) == 3): # Do we have helpText for our next arg?
        self.argPrompt += self.args[-1] + self.cmdRef[len(self.args)][2]
      else:
        self.argPrompt += self.args[-1] + " :"
      self.buf = self.argPrompt
      self.cX = len(self.buf)
