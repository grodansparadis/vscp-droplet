#!/usr/bin/sh
python spiffsgen.py 196608 web build/spiffs.bin
esptool.py --chip esp32 --port /dev/ttyUSB0 write_flash -z 0x3d0000 build/spiffs.bin