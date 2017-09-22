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
  allowedChars.append(32) #   whitespace(spacebar)
  allowedChars.append(33) # ! bang
  allowedChars.append(37) # % percent
  allowedChars.append(43) # + plus
  allowedChars.append(45) # - dash
  allowedChars.append(46) # . dot
  allowedChars.append(47) # / forward slash
  allowedChars.append(58) # : colon
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
   -Where type can be either s(string), i(decimal integer)
   --if type=='s' then desc is a regexp that must match
   --if type=='i' then desc is a range given as 'min_max' inclusive
   -Where desc is either regex for 's' OR a range for 'i'
   -Where helpText is optional and shown when inputting, useful when multiple args present

   DO NOT make keys where (keyX.startswith(keyY) == True)
   Example: 'foo' and 'foo-bar' are NOT allowed, while 'foo-f' and 'foo-b' are allowed

   '''
  cmds = {
    'pkt-min-size' : ['self.cap._set_minPktSize()', [['i', '60_100']]], # Couldn't get property set to work here
    'pkt-max-size' : ['self.cap._set_maxPktSize()', [['i', '1000_8000']]],
    'pkt-size-range' : ['self.cap.setPktSizeRange()', [['i', '60_70', ' min:'], ['i', '1000_1500', ' max:']]],
    'interface' : ['self.cap.setInterface()', [['s', '^[\w]{2,}[0-9]{1,}$']]],
    'save-file' : ['self.cap.save()', []],
    'save-as-file' : ['self.cap.saveAs()', [['s', '^[\w.-_,:@]*$']]],

    'tx-all' : ['self.tx(1,len(self.cap),)', [['i', '0_999', ' repeat:']]],
    'tx-pkt' : ['self.tx(self.ppadCY+1,self.ppadCY+1,)', [['i', '0_999', ' repeat:']]],
    'tx-range' : ['self.tx()', [['i', '1_999', ' first:'], ['i', '1_999', ' last:'], ['i', '0_999', ' repeat:']]],
    'rx-all' : ['self.rx()', [['i', '0_999', ' count:']]],
    'rx-filter' : ['self.rx()', [['i', '0_999', ' count:'], ['s', '^[\w. ]{0,}$', ' filter:']]],

    'generator' : ['self.modPkt(\'generator\',)', [['i', '1_255', ' count:'], ['i', '-16_16', ' step:']]],
    'mask' : ['self.modPkt(\'mask\',)', [['s', '^[0-9,a-f,.,:,-]+$', ' mask:']]],
    'sleep' : ['self.modPkt(\'sleep\',)', [['i', '1_' + str((10 ** cfg.pktIDWidth) - 1), ' seconds:']]],
    'jump' : ['self.modPkt(\'jump\',)', [['i', '1_' + str((10 ** cfg.pktIDWidth) - 1), ' pid:']]],
    'insert-sleep' : ['self.modPkt(\'insert-sleep\',)', [['i', '1_' + str((10 ** cfg.pktIDWidth) - 1), ' seconds:']]],
    'insert-jump' : ['self.modPkt(\'insert-jump\',)', [['i', '1_' + str((10 ** cfg.pktIDWidth) - 1), ' pid:']]]

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
    self.history = cfg.mBufHistory # Our CLI history
    self.historyPtr = -1 # Pointer to current history item 

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

    # Set history pointer to no history
    self.historyPtr = -1

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
        cfg.mBufHistory.insert(0, [self.func, self.args])
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
    if curses.keyname(c) == '^?' or curses.keyname(c) == 'KEY_BACKSPACE': # Backspace
      if(len(self.buf) > len(self.argPrompt)):
        self.buf = self.buf[:len(self.buf)-1]
        self.cX -= 1

    elif(c == curses.KEY_RIGHT):
      if(self.cX < len(self.buf)):
        self.cX += 1

    elif(c == curses.KEY_LEFT):
      if(self.cX > 0):
        self.cX -= 1

    elif c == curses.KEY_UP :
      if self.historyPtr < len(self.history) - 1:
        self.historyPtr += 1
        self.buf = self.history[self.historyPtr][0]
        self.cX = len(self.buf)

    elif c == curses.KEY_DOWN:
      if self.historyPtr == 0:
        self.resetPrompt()
      elif self.historyPtr > -1:
        self.historyPtr -= 1
        self.buf = self.history[self.historyPtr][0]
        self.cX = len(self.buf)

    elif(curses.keyname(c) == '^A'): # Goto beginning of line
      self.cX = len(self.argPrompt)

    elif(curses.keyname(c) == '^E'): # Goto end of line
      self.cX = len(self.buf)
      
    elif(curses.keyname(c) == '^U'): # Goto beginning of line and clear line
      self.cX = len(self.argPrompt)
      self.buf = self.argPrompt

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
    arg = self.buf[len(self.argPrompt):].strip()
    if(len(arg) < 1):
      return

    if(curses.keyname(c) == '^I'): # TAB
      return

    argDef = self.cmdRef[len(self.args)]
    if(curses.keyname(c) == '^J' or curses.keyname(c) == '^M'): # Enter/Return \n
      if(argDef[0] == 'i'):
        if(arg.startswith('-')):
          argSign = -1
          arg = arg[1:]
        else:
          argSign = 1

        if(arg.isdigit()):
          rMin, rMax = argDef[1].split("_")
          rMin = int(rMin)
          rMax = int(rMax)
          arg = int(arg) * argSign
          if((arg >= rMin) and (arg <= rMax)):
            self.args.append(str(arg))
          else:
            self.msg = self.buf + "   [Out of Range " + str(rMin) + "-" + str(rMax) + "]"
            return
        else:
          self.msg = self.buf + "   [Bad Input]"
          return

      elif(argDef[0] == 's'):
        if(re.search(argDef[1], arg)):
          self.args.append("\'" + str(arg) + "\'")
        else:
          self.msg = self.buf + "   [Bad Input]"
          return

      # hex input doesn't really work
      # Just keeping it incase I feel like fixing it, but it probably won't ever be used
      elif(argDef[0] == 'h'):
        if(arg.startswith('-')):
          argSign = -1
          arg = arg[1:]
        else:
          argSign = 1

        if(argDef[1].startswith('-')):
          rMinSign = -1
          argDef[1] = argDef[1][1:]
        else:
          rMinSign = 1
        
        if(re.search("^[0-9,a-f]+$", arg)):
          if((len(arg) % 2) != 0):
            self.msg = self.buf + "   [Nibble Input:Expected full bytes]"
            return

          rMin, rMax = argDef[1].split("-")
          rMin = int('0x' + rMin, 16) * rMinSign
          rMax = int('0x' + rMax, 16)
          arg = int('0x' + arg, 16) * argSign
          if((arg >= rMin) and (arg <= rMax)):
            self.args.append(str(arg))
          else:
            self.msg = self.buf + "   [Out of Range " + str(hex(rMin)) + "-" + str(hex(rMax)) + "]"
            return
        else:
          self.msg = self.buf + "   [Bad Input:Expected hex]"
          return

    # Are we done collecting args?
    if(len(self.args) == len(self.cmds[self.func][1])):
      self.resetPrompt()
    else:
      if(len(self.cmdRef[len(self.args)]) == 3): # Do we have helpText for our next arg?
        self.argPrompt += self.args[-1].strip("\'") + self.cmdRef[len(self.args)][2]
      else:
        self.argPrompt += self.args[-1].strip("\'") + " :"
      self.buf = self.argPrompt
      self.cX = len(self.buf)
