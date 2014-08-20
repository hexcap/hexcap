'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import datetime
import sys

######################
# Global definitions #
######################

# Debugging globals
debug = True

if(debug):
  dbgF = open(sys.path[0] + '/hexcap.log', 'a', 0)

def dbg(msg):
  if(debug):
    dt = datetime.datetime.now()
    ts = dt.strftime("%m/%d/%y %H:%M:%S.%f") + " "
    dbgF.write(ts + str(msg) + '\n')

# Removes all characters in passed string not in hexChars
def cleanHexStr(s):
  rv = ""
  for c in s:
    if(ord(c) in hexChars):
      rv += c
  return rv

# Converts a binary string to a hex string
# Takes binary string and returns hex string
def binStrToHexStr(s):
  leadZeros = (len(s) - len(s.lstrip('0')))
  if(leadZeros < 4):
    return hex(int('0b' + s, 2)).split('0x')[1].rstrip("L")
  else:
    leadZeros = (leadZeros // 4) + (leadZeros % 4)
    return ''.join('0' * leadZeros) + hex(int('0b' + s, 2)).split('0x')[1].rstrip("L")

# Converts a hex string to a binary string
# Takes hex string and returns binary string
def hexStrToBinStr(s):
  leadZeros = 0
  for c in s:
    if(c == '0'):
      leadZeros += 4
    else:
      leadZeros += 4 - len(bin(int('0x' + c, 16)).split('0b')[1])
      break
  return ''.join('0' * leadZeros) + bin(int('0x' + s, 16)).split('0b')[1]

# Increments a hexStr(hs) by step respecting passed mask
# Returns incremented hexStr respecting delimters
def incHexStr(hs, mask, step=1):
  if(len(hs) != len(mask)):
    dbg("Fatal Length Error in incHex()")

  if(step > 0):
    for ii in xrange(step):
      for jj in xrange(len(hs) - 1, 0, -1):
        if(ord(hs[jj]) in hexChars):
          if(hs[jj] == 'f'):
            hs = hs[:jj] + '0' + hs[jj+1:]
          elif(int(hs[jj], 16) | int(mask[jj], 16) != 15):
            hs = hs[:jj] + hex(int(hs[jj], 16) + 1)[2] + hs[jj+1:]
            break
  else:
    for ii in xrange(0, step, -1):
      for jj in xrange(len(hs) - 1, 0, -1):
        if(ord(hs[jj]) in hexChars):
          if(hs[jj] == '0'):
            hs = hs[:jj] + 'f' + hs[jj+1:]
          elif(int(hs[jj], 16) | int(mask[jj], 16) != int(mask[jj], 16)):
            hs = hs[:jj] + hex(int(hs[jj], 16) - 1)[2] + hs[jj+1:]
            break
  return hs

# We can't count past 99,999
pktIDWidth = 5

# Allowed hexidecimal characters
# Can't use string.hexdigits since it has caps
hexChars = []
for x in xrange(0,10):
  hexChars.append(ord(str(x)))
hexChars.append(ord('a'))
hexChars.append(ord('b'))
hexChars.append(ord('c'))
hexChars.append(ord('d'))
hexChars.append(ord('e'))
hexChars.append(ord('f'))

# mini-buffer CLI history
mBufHistory = []
