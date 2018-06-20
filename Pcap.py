#! /usr/bin/python3
# coding: utf-8

import sys
import struct
import collections
import ipaddress
import datetime

class Packet:
    IP = collections.namedtuple('IP', 'src dst')
    ESP = collections.namedtuple('ESP', 'spi sequence')
    TCP = collections.namedtuple('TCP', 'srcport dstport')
    UDP = collections.namedtuple('UDP', 'srcport dstport')
    def __init__(self, metadata, src, dst, tcp=None, esp=None, udp=None, data=None):
        metadata['timestamp'] = datetime.datetime.fromtimestamp(metadata['timestamp']) 
        self.metadata = metadata
        self.ip = Packet.IP(ipaddress.ip_address(src), ipaddress.ip_address(dst))
        self.esp = esp
        assert tcp or udp
        if tcp:
            self.tcp = Packet.TCP(**tcp)
            self.udp = None
        elif udp:
            self.udp = Packet.UDP(**udp)
            self.tcp = None
        self.data = data

class Pcap:
    def __init__(self, filename):
        self.error = None
        self.fp = open(filename, 'rb')
        blocktype,blockdata = self.nextblock()
        if blocktype != 0x0a0d0d0a or not self.decodeheader(blockdata):
            raise Exception("{} is not a pcapng file".format(filename))

    def __iter__(self):
        while True:
            if self.error:
                return
            blocktype,blockdata = self.nextblock()
            if blocktype == 0x0a0d0d0a:
                if not self.decodeheader(blockdata):
                    return
            elif blocktype == 1:
                self.decodeinterface(blockdata)
            elif blocktype == 6:
                block = self.decodeenhancedpacket(blockdata)
                if block:
                    yield block
            elif blocktype == None:
                return

    def nextblock(self):
        buf = self.fp.read(8)
        if len(buf) != 8:
            self.error = "truncated block"
            return None,None
        blocktype,length = struct.unpack('=LL', buf)
        if length%4 != 0:
            self.error = "bad block length"
            return None,None
        blockdata = self.fp.read(length-12)
        if len(blockdata) != length-12:
            self.error = "truncated block"
            return None,None
        buf = self.fp.read(4)
        if len(buf) != 4:
            self.error = "truncated block"
            return None,None
        length2, = struct.unpack('=L', buf)
        if length2 != length:
            self.error = "incoherent block length"
            return None,None
        return blocktype, blockdata

    def decodeheader(self, header):
        bo,major,minor = struct.unpack_from('=LHH', header)
        if minor != 0:
            self.error = "bad minor version"
        if major != 1:
            self.error = "bad major version"
        if bo != 0x1a2b3c4d:
            self.error = "bad BO magic"
        self.interfaces = []
        return self.error is None

    def decodeinterface(self, interface):
        intf = dict(
            linktype = struct.unpack_from('=H', interface)[0],
            tsresol  = 10**-6)
        for optioncode,optionvalue in self.decodeoptions(interface[8:]):
            if optioncode == 9:
                # time resolution
                value = optionvalue[0]
                if value & 0x80:
                    tsresol = 2**-(value & 0x7f)
                else:
                    tsresol = 10**-value
                intf['tsresol'] = tsresol
            elif optioncode == 2:
                intf['name'] = optionvalue.decode('utf-8')
            elif optioncode == 11:
                intf['filter'] = optionvalue
            elif optioncode == 12:
                intf['os'] = optionvalue.decode('utf-8')
        self.interfaces.append(intf)

    def decodeenhancedpacket(self, packet):
        interface,timestampH,timestampL,capturedlen,originallen = struct.unpack_from('=LLLLL', packet)
        packet = packet[20:20+originallen]
        if interface >= len(self.interfaces):
            self.error = "unknown interface"
            return
        interface = self.interfaces[interface]
        if interface['linktype'] != 1 or capturedlen != originallen:
            return # not an Ethernet packet or truncated packet
        interface['timestamp'] = ((timestampH<<32) + timestampL) * interface['tsresol']
        if len(packet) != originallen:
            self.error = "bad packet length"
            return
        ethertype, = struct.unpack_from('!h', packet, 12)
        if ethertype != 0x800:
            return # not an Ethernet/IPv4 packet
        IHL = 4 * (packet[14] & 0x0f)
        protocol = packet[23]
        srcip,dstip = struct.unpack_from('!LL', packet, 26)
        esp = None
        packet = packet[14 + IHL:]
        if protocol == 50:
            # assuming null encryption and ICV is 12 bytes long
            if len(packet) < 8 + 2 + 12:
                return
            spi,sequence = struct.unpack_from('!2L', packet)
            protocol = packet[-13]
            padlen = packet[-14]
            packet = packet[8:-14-padlen]
            esp = dict(spi=spi, sequence=sequence)
        if protocol == 6:
            srcport,dstport = struct.unpack_from('!2H', packet)
            dataoffset = (packet[12] & 0xf0) >> 2
            data = packet[dataoffset:]
            return Packet(interface, srcip, dstip, esp=esp, tcp=dict(srcport=srcport, dstport=dstport), data=data)
        elif protocol == 17:
            srcport,dstport = struct.unpack_from('!2H', packet)
            data = packet[8:]
            return Packet(interface, srcip, dstip, esp=esp, udp=dict(srcport=srcport, dstport=dstport), data=data)

    def decodeoptions(self, options):
        offset = 0
        while True:
            if len(options) < 4:
                return
            code,length = struct.unpack_from('=HH', options, offset)
            if code == 0:
                return
            if len(options) < 4+length:
                return
            value = options[offset+4:offset+4+length]
            offset += 4 * ((4+length) // 4)
            if length % 4:
                offset += 4
            yield code,value
