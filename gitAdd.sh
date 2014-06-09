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
 
for F in cp.py cfg.py hexcap.py hexscreen.py section.py capture.py packet.py layer.py assoc.py __init__.py pdiff.sh minibuffer.py
do
  /usr/bin/git add $BDIR/hexcap/$F
done

for F in `ls $BDIR/hexcap/traces/`
do
  /usr/bin/git add $BDIR/hexcap/traces/$F
done

# Grab all of dpkt except .pyc files  
for F in `ls $BDIR/dpkt-read-only/`
do
  /usr/bin/git add $BDIR/dpkt-read-only/$F
done

for F in `ls $BDIR/dpkt-read-only/dpkt/|grep .py`
do
  /usr/bin/git add $BDIR/dpkt-read-only/dpkt/$F
done

for F in `ls $BDIR/dpkt-read-only/tests/`
do
  /usr/bin/git add $BDIR/dpkt-read-only/tests/$F
done

for F in `ls $BDIR/dpkt-read-only/examples/`
do
  /usr/bin/git add $BDIR/dpkt-read-only/examples/$F
done

