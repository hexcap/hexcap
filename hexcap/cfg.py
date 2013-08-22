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

import datetime

######################
# Global definitions #
######################

# Debugging globals
debug = False

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
hexChars = []
for x in xrange(0,10):
  hexChars.append(ord(str(x)))
hexChars.append(ord('a'))
hexChars.append(ord('b'))
hexChars.append(ord('c'))
hexChars.append(ord('d'))
hexChars.append(ord('e'))
hexChars.append(ord('f'))
