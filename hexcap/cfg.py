'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import datetime

######################
# Global definitions #
######################

# Debugging globals
debug = True

if(debug):
  dbgF = open('hexcap.log', 'a', 0)

def dbg(msg):
  if(debug):
    dt = datetime.datetime.now()
    ts = dt.strftime("%m/%d/%y %H:%M:%S.%f") + " "
    dbgF.write(ts + str(msg) + '\n')

# Converts a binary string to a hex string
# Takes binary string and returns hex string
def binStrToHexStr(s):
  leadZeros = (len(s) - len(s.lstrip('0')))
  if(leadZeros < 4):
    return hex(int('0b' + s, 2)).split('0x')[1]
  else:
    leadZeros = (leadZeros // 4) + (leadZeros % 4)
    return ''.join('0' * leadZeros) + hex(int('0b' + s, 2)).split('0x')[1]

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

  dbg("leadZeros:" + str(leadZeros))
  return ''.join('0' * leadZeros) + bin(int('0x' + s, 16)).split('0b')[1]

#    leadZeros += (len(s) - len(s.lstrip('0'))) * 4
#    leadZeros = 4 - len(bin(int('0x' + s[0], 16)).split('0b')[1])


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
