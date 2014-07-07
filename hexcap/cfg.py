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
