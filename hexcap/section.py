#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

import cfg
from assoc import Assoc

class Section:
  def __init__(self, sectId, pos):
    self.ID = sectId # Our layer ID
    self.position = pos # Our relative position in the ordering of columns

    self.c = Assoc() # Assoc of columns
    self.exposed = False # Is this section showing?
    self.exposable = True # Can the exposed boolean be toggled?
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

  def __repr__(self):
    rv = "\nID:" + self.ID
    rv += " exposed:" + str(self.exposed)
    rv += " width:" + str(self.width)
    rv += " visible:" + str(self.visible)
    rv += " RO:" + str(self.RO) + "\n"
    for k,v in self.c.iteritems():
      rv += "  col:" + k + " w:" + str(v) + " "
    return rv

  def dump(self):
    return self.__repr__()
