#!/bin/bash
BDIR=`pwd`

for F in setup.py README.txt LICENSE.txt compile.sh gitAdd.sh
do
  /usr/bin/git add $BDIR/$F
done

for F in hexcap
do
  /usr/bin/git add $BDIR/bin/$F
done
 
for F in cp.py cfg.py hexcap hexscreen.py section.py capture.py packet.py layer.py assoc.py __init__.py pdiff.sh minibuffer.py
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
