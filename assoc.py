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
      if(k is None):
        rv += "[" + str(ii) + "]:=\'" + str(v) + "\' "
      else:
        rv += "['" + k + "']:=\'" + str(v) + "\' "
    return rv

  # Returns index of self._vals list for passed key
  # SHOULD never be called outside of class
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
      try:
        ii = self.__getIndex__(key)
        self._vals[ii] = list(((self._vals[ii][0]), (val)))
      except IndexError:
        self._vals.append(list(((None), (val))))
    elif(isinstance(key, str)):
      self._vals.append(((key), (val)))
    else:
      raise TypeError, "unknown index type"

  def __getitem__(self, key):
    return self._vals[self.__getIndex__(key)][1]

  def __iter__(self):
    return AssocIter(self._vals, False)

  def __delitem__(self, key):
    del self._vals[self.getIndex(key)]

  def __len__(self):
    return len(self._vals)

  def __contains__(self, val):
    for k,v in self._vals:
      if(v == val):
        return True
    return False
      
  def iteritems(self):
    return AssocIter(self._vals, True)

  def items(self):
    rv = []
    ii = -1
    for ii in xrange(len(self._vals)):
      if(self._vals[ii][0] == None): 
        rv.append(list(((str(ii)), (self._vals[ii][1]))))
      else:
        rv.append(list(((self._vals[ii][0]), (self._vals[ii][1]))))
    return rv

  def remove(self, key):
    self.__delitem__(key)

  def reverse(self):
    self._vals.reverse()

  def append(self, x):
    self._vals.append(((None), (x)))

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
        self._vals.append(list(((None), (v))))
    else:
      raise TypeError, "unknown type"

  def insert(self, key, val):
    self._vals.insert(self.getIndex(key), list(((None), (val))))

  # Can return either a string or integer
  def index(self, val):
    ii = -1
    for k,v in self._vals:
      ii += 1
      if(v == val):
        if(k is None):
          return ii
        else:
          return k
    raise ValueError, "value not found"

  def count(self, val):
    cnt = 0
    for k,v in self._vals:
      if(val == v):
        cnt += 1
    return cnt

class AssocIter():
  def __init__(self, vals, keys):
    self._vals = vals
    self.keys = keys
    self.ii = -1

  def __iter__(self):
    return self

  def next(self):
    self.ii += 1
    if(self.ii < len(self._vals)):
      if(self.keys):
        if(self._vals[self.ii][0] is None):
          return str(self.ii), self._vals[self.ii][1]
        else:
          return self._vals[self.ii][0], self._vals[self.ii][1]
      else:
        return self._vals[self.ii][1]
    else:
      raise StopIteration

# TODO
#  def __iter__(self):
# def next(self):
# def sort(self):

'''Test'''
'''
print "\nTest basic assignment"
ass = Assoc()
ass[0] = 'bob'
ass.append("mike")
ass['dog'] = 'rex'
ass['1'] = 'string'
print ass[0]
print ass[1]
print ass[2]
print repr(ass)
ass[2] = 'fido'
print repr(ass)

print "\nTest loops"
for v in ass:
  print "v:" + str(v)

for ii in xrange(len(ass)):
  print "ii:" + str(ii) + " v:" + ass[ii]

for k,v in ass.items():
  print "k:" + str(k) + " v:" + str(v)

for k,v in ass.iteritems():
  print "k:" + str(k) + " v:" + str(v)

print "\nTest append() and extend()"
ass.append("steve")
stup = []
stup.append("foo")
stup.append("bar")
stup.append("foo")
print repr(stup)
ass.extend(stup)
print repr(ass)

print "\nTest index() and count()"
print str(stup.index('foo')) + " "
print str(ass.index('foo')) + " "
print ass.index('fido') + " "
#print ass.index('NA')
print ass.count('foo')

print "\nTest reverse()"
ass.reverse()
print repr(ass)

print "\nTest pop()"
print ass.pop()
'''
