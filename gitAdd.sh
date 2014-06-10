#!/bin/ksh
BDIR=`pwd`
GIT=/usr/local/bin/git


for F in setup.py README.txt LICENSE.txt compile.sh gitAdd.sh
do
  $GIT add $BDIR/$F
done

for F in hexcap
do
  $GIT add $BDIR/bin/$F
done
 
for F in cp.py cfg.py hexcap.py hexscreen.py section.py capture.py packet.py layer.py assoc.py __init__.py pdiff.sh minibuffer.py
do
  $GIT add $BDIR/hexcap/$F
done

for F in `ls $BDIR/hexcap/traces/`
do
  $GIT add $BDIR/hexcap/traces/$F
done

for F in `ls $BDIR/dpkt-read-only/`
do
  $GIT add $BDIR/dpkt-read-only/$F
done

for F in `ls $BDIR/dpkt-read-only/dpkt/|grep .py$`
do
  $GIT add $BDIR/dpkt-read-only/dpkt/$F
done

for F in `ls $BDIR/dpkt-read-only/tests/`
do
  $GIT add $BDIR/dpkt-read-only/tests/$F
done

for F in `ls $BDIR/dpkt-read-only/examples/`
do
  $GIT add $BDIR/dpkt-read-only/examples/$F
done

