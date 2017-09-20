#!/bin/bash

# Outputs paginated packet diff of two pcap files
# Must be in the same directory as cp.py

./cp.py $1 >pdiffOut_1.txt
./cp.py $2 >pdiffOut_2.txt
diff -b pdiffOut_1.txt pdiffOut_2.txt |less
rm pdiffOut_1.txt
rm pdiffOut_2.txt
