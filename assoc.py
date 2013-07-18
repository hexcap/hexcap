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

  # Returns index of self._vals list for passed key
  def __getIndex__(self, key):
    if(isinstance(key, int)):
      if((key < len(self._vals)) and (key > -1)):
        return key
      else:
        raise IndexError, "index out of range"        
    elif(isinstance(key, str)):
      ii = -1
      for k,v in self._vals:
        ii += 1
        if(key == k):
          return ii
      raise IndexError, "nonexistent string index"
    else:
      raise TypeError, "unknown index type"

  def __setitem__(self, key, val):
    if(isinstance(key, int)):
      index = self.__getIndex__(key)
      self._vals[index] = list(((''), (val)))
    elif(isinstance(key, str)):
      self._vals.append(((key), (val)))
    else:
      raise TypeError, "unknown index type"

  def __getitem__(self, key):
    index = self.__getIndex__(key)
    if(len(self._vals[index][0]) > 0):
      return self._vals[index][0], self._vals[index][1]
    else:
      return key, self._vals[self.__getIndex__(key)][1]

  def __delitem__(self, key):
    del self._vals[self.getIndex(key)]

  def __len__(self):
    return len(self._vals)

  def __contains__(self, val):
    for k,v in self._vals:
      if(v == val):
        return True
    return False
      
  def remove(self, key):
    self.__delitem__(key)

  def reverse(self):
    self._vals.reverse()

  def append(self, x):
    self._vals.append(((''), (x)))

  def pop(self):
    return self._vals.pop()[1]

  def extend(self, L):
    if(len(L) < 1):
      return

    if(isinstance(L, Assoc)):
      for k,v in L:
        self._vals.append(list(((k), (v))))
    elif(isinstance(L, list)):
      for v in L:
        self._vals.append(list(((''), (v))))
    else:
      raise TypeError, "unknown type"

  def insert(self, key, val):
    self._vals.insert(self.getIndex(key), list(((''), (val))))

  def index(self, val):
    ii = -1
    for k,v in self._vals:
      ii += 1
      if(v == val):
        if(len(k) > 0):
          return k
        else:
          return ii
    raise ValueError, "value not found"

  def count(self, val):
    cnt = 0
    for k,v in self._vals:
      if(val == v):
        cnt += 1
    return cnt


# TODO
#  def __iter__(self):
# def next(self):
# def sort(self):

'''Test'''
ass = Assoc()
ass.append("cat")
ass['rex'] = 'dog'
ass['1'] = 'string'
print ass[0]
print ass[1]
print ass[2]
print repr(ass)
ass[2] = 'fido'
print repr(ass)
print ass.pop()
print repr(ass)
ass.append("kitty")

print "**FOR**"
for k,v in ass:
  print "k:" + str(k) + " v:" + str(v)

for v in ass:
  print " v:" + str(v)

print "*END FOR*"

stup = []
stup.append("foo")
stup.append("bar")
print repr(stup)
ass.extend(stup)
print repr(ass)
