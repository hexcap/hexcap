#!/usr/bin/env python

from distutils.core import setup
import hexcap

setup(name='hexcap',
      version=hexcap.__version__,
      author=hexcap.__author__,
      url=hexcap.__url__,
      description='pcap file hex editor',
      packages=[ 'hexcap' ])

