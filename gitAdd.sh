#!/bin/bash
BDIR=`pwd`

/usr/bin/git add $BDIR/gitAdd.sh

for F in setup.py README.txt LICENSE.txt
do
  /usr/bin/git add $BDIR/$F
done

for F in cp.py cfg.py hexcap.py section.py capture.py packet.py layer.py assoc.py __init__.py
do
  /usr/bin/git add $BDIR/hexcap/$F
done

for F in `ls $BDIR/hexcap/traces/`
do
  /usr/bin/git add $BDIR/hexcap/traces/$F
done

for F in __init__.py stp.py ethernet.py igmp.py dot1q.py edp.py llc.py
do
  /usr/bin/git add $BDIR/dpkt-read-only/dpkt/$F
done
