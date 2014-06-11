#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import os
import curses
import sys
import time

# hexcap specific imports
import hexscreen
import cfg
import capture

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

mainScr = hexscreen.HexScreen()
mainScr.initPad(pc)

while True:
  try:
    mainScr.refresh()
    c = mainScr.getch()
    cfg.dbg("KeyPress c:" + repr(c) + " ctrl:" + repr(curses.keyname(c)))

    if(c != -1):
      if(mainScr.mBufFocus):
        mainScr.inputToMBuf(c)

      else:
        if(mainScr.insert):
          if(c in cfg.hexChars):
            mainScr.handleInsert(c)

        if(curses.keyname(c) == '^X'):
          mainScr.toggleMBuf()
            
        elif(c == curses.KEY_RIGHT):
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
          try:
            pc.save()
          except IOError:
            mainScr.mBufMsg = "Error writing file: " + pc.fName

        elif(curses.keyname(c) == '<'): # Shift left 1 column
          mainScr.shiftColumn(-1)

        elif(curses.keyname(c) == '>'): # Shift right 1 column
          mainScr.shiftColumn(1)

        elif(curses.keyname(c) == '^R'): # Reread packet capture from disk
          try:
            f = open(pc.fName, 'rb')
          except IOError:
            mainScr.mBufMsg = "Error reading file: " + pc.fName
          else:
            pc = capture.Capture(f, pc.fName)
            f.close()
            mainScr.initPad(pc)

        elif(curses.keyname(c) == '^N'): # Toggle INS/NAV mode
          mainScr.toggleInsert()

        elif(curses.keyname(c) == '^@'): # Set new mark (^@ == 'CTRL-SPACE')
          mainScr.toggleMark()

        elif(curses.keyname(c) == '^Y'): # Paste packet(s)
          mainScr.paste()

        elif(curses.keyname(c) == '^W'): # Yank packet(s)
          mainScr.yank()

        elif(curses.keyname(c) == '^K'): # Yank single packet
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

