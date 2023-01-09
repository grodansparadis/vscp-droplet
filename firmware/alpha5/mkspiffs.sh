#!/usr/bin/sh
python spiffsgen.py 327680 web build/spiffs.bin
esptool.py --chip esp32 --port /dev/ttyUSB1 write_flash -z 0x3b0000 build/spiffs.bin
