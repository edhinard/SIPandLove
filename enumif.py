#! /usr/bin/python3
# coding: utf-8
# Use those functions to enumerate all interfaces available on the system using Python.
# found on <http://code.activestate.com/recipes/439093/#c1>

import sys
import socket
import fcntl
import struct
import array
import ipaddress 

def all_interfaces():
    is_64bits = sys.maxsize > 2**32
    SIZEOF_IFREQ = 40 if is_64bits else 32
    IFNAMSIZ = 16
    SIZEOF_SA_FAMILY = 4
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8 # initial value
    while True:
        _bytes = max_possible * SIZEOF_IFREQ
        names = array.array('B')
        for i in range(0, _bytes):
            names.append(0)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', _bytes, names.buffer_info()[0])
        ))[0]
        if outbytes == _bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tobytes()
    ifaces = []
    for i in range(0, outbytes, SIZEOF_IFREQ):
        name,addr= struct.unpack_from('16s4x4s', namestr, i)
        ifaces.append((bytes.decode(name.strip(b'\0')), ipaddress.ip_address(addr)))
    return ifaces


ifs = all_interfaces()
for i in ifs:
    print("%12r   %r" % (i[0], i[1]))
