#!/usr/bin/env python

import sys
sys.path.insert(0, '/home/smutt/hacking/python/hexcap/dpkt-read-only/dpkt')
import pcap
import ethernet
import tcp

if(len(sys.argv) > 2):
  pcIn = pcap.Reader(open(sys.argv[1]))
  pcOut = pcap.Writer(open(sys.argv[2], 'wb'))
  for ts, pkt in pcIn:
    eth = ethernet.Ethernet(pkt)
    ip = eth.data
    otcp = ip.data

    newTCP = tcp.TCP()
    newTCP.dport = otcp.dport
    newTCP.sport = otcp.sport
    newTCP.win = otcp.win
    newTCP.sum = otcp.sum
    newTCP.flags = otcp.flags
    newTCP.seq = otcp.seq
    newTCP.ack = otcp.ack
    newTCP.data = otcp.data

    # When we set the TCP offset we corrupt the tcp.data field
    # Still not sure why but nothing I seem to do resolves it
#    newTCP._set_off(otcp._get_off())
    newTCP.off_x2 = otcp.off_x2


    ip.data = newTCP

    pcOut.writepkt(ethernet.Ethernet.pack(eth), ts)
















