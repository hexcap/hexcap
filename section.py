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

import cfg
import assoc
from collections import OrderedDict

class Section:
  def __init__(self, sectId, pos):
    self.ID = sectId # Our layer ID
    self.position = pos # Our relative position in the ordering of columns

    self.c = OrderedDict() # OrderedDict of columns
#    self.c = Assoc() # Assoc of columns
    self.exposed = False # Is this section showing?
    self._width = 0 # Width of complete section
    self.visible = True # Is this section currently visible?
    self.RO = False # Is this section ReadOnly? Can it be modified by the user

  def _get_width(self):
    if(self.exposed):
      return self._width
    else:
      return len(self.ID) + 3
  width = property(_get_width)

  def append(self, name, w):
    self.c[name] = w
    self._width += w + 1

  # For debugging only
  def dump(self):
    rv = ''
    rv += "\nID:" + self.ID
    rv += " exposed:" + str(self.exposed)
    rv += " width:" + str(self.width)
    rv += " visible:" + str(self.visible)
    rv += " RO:" + str(self.RO) + "\n"
#    for ii in xrange(len(self.c)):
#      rv += "col:" + k + " w:" + str(v) + " "
    for k,v in self.c.iteritems():
      rv += "col:" + k + " w:" + str(v) + " "
    return rv
