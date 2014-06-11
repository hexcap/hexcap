#!/usr/bin/env python

'''
Copyright (c) 2014, Andrew McConachie <smutt@depht.com>
All rights reserved.
'''

from distutils.core import setup
import hexcap
import dpkt-read-only/dpkt

setup(name = 'hexcap',
      version = hexcap.__version__,
      author = hexcap.__author__,
      author_email = hexcap.__author_email__,
      license = hexcap.__license__,
      url = hexcap.__url__,
      description = 'curses based pcap file hex editor',
      long_description = open('README.txt').read(),
      packages = ['hexcap'])
