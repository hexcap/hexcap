#!/bin/bash

cd ../pyinstaller
python pyinstaller.py --clean --onefile --noconfirm --name hc ../Hexcap/hexcap/hexcap.py
mv hc/dist/hc ../Hexcap/bin/hexcap
chmod 755 ../Hexcap/bin/hexcap