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

'''A proper associative array for Python'''

class Assoc():
  def __init__(self):
    self._vals = []

  def append(self, x):
    self._vals.append(((''),(x)))

  def pop(self):
    return self._vals.pop()[1]

  def __setitem__(self, key, val):
    if(isinstance(key, int)):
      try:
#        self._vals[key][0] = ''
        self._vals[key][1] = val
      except:
        raise IndexError
    elif(isinstance(key, str)):
      for k,v in self._vals:
        if(key == k):
          v = val
          return
      self._vals.append(((key), (val)))
    else:
      raise TypeError

  def __getitem__(self, key):
    if(isinstance(key, int)):
      try:
        return self._vals[key][1]
      except:
        raise IndexError
    elif(isinstance(key, str)):
      for k,v in self._vals:
        if(key == k):
          return v
      raise IndexError
    else:
      raise TypeError

  def __delitem__(self, key):
    if(isinstance(key, int)):
      try:
        del self._vals[key]
      except:
        raise IndexError
    elif(isinstance(key, str)):
      ii = -1
      for k,v in self._vals:
        ii += 1
        if(key == k):
          del self._vals[ii]
      raise IndexError
    else:
      raise TypeError
    
  def __contains__(self, key):
    if(isinstance(key, int)):
      if(key == abs(key)):
        if(key < len(self._vals)):
          return True
        else:
          return False
    elif(isinstance(key, str)):
      for k,v in self._vals:
        if(key == k):
          return True
      return False
    else:
      raise TypeError
      
  def reverse(self):
    return self._vals.reverse()

  def __len__(self):
    return len(self._vals)

  def remove(self, key):
    self.__delitem__(key)

  def __repr__(self):
    rv = ''
    ii = -1
    for k,v in self._vals:
      ii += 1
      if(len(k) > 0):
        rv += "['" + k + "']:=" + str(v) + " "
      else:
        rv += "[" + str(ii) + "]:=" + str(v) + " "
    return rv

#  def __iter__(self):


'''Test'''
ass = Assoc()
ass.append("cat")
ass['rex'] = 'dog'
ass['1'] = 'string'
print ass[0]
print ass[1]
print repr(ass)
ass[1] = 'fido'
print repr(ass)
#print ass['dog']
