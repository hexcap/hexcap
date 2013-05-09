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

######################
# Global definitions #
######################

# Toggle debugging output
debug = True

# We can't count past 99,999
pktIDWidth = 5

# Key Constants
# Consider using curses.keyname(k)
KEY_CTRL_SPACE = 0
KEY_CTRL_B = 2
KEY_CTRL_F = 6
KEY_CTRL_I = 9
KEY_CTRL_K = 11
KEY_CTRL_Q = 17
KEY_CTRL_R = 18
KEY_CTRL_S = 19
KEY_CTRL_U = 21
KEY_CTRL_W = 23
KEY_CTRL_Y = 25
KEY_CTRL_H = 263

# Allowed hexidecimal characters
hexChars = []
for x in xrange(0,9):
  hexChars.append(ord(str(x)))
hexChars.append(ord('a'))
hexChars.append(ord('b'))
hexChars.append(ord('c'))
hexChars.append(ord('d'))
hexChars.append(ord('e'))
hexChars.append(ord('f'))

