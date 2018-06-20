#! /usr/bin/python3
# coding: utf-8

import sys
import struct
import collections
import ipaddress

class Packet:
    IP = collections.namedtuple('IP', 'src dst')
    ESP = collections.namedtuple('ESP', 'spi sequence')
    TCP = collections.namedtuple('TCP', 'srcport dstport')
    UDP = collections.namedtuple('UDP', 'srcport dstport')
    def __init__(self, timestamp, src, dst, tcp=None, esp=None, udp=None, data=None):
        self.timestamp = timestamp
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
        link, = struct.unpack_from('=H', interface)
        self.interfaces.append(link)
        for optioncode,optionvalue in self.decodeoptions(interface[8:]):
            pass

    def decodeenhancedpacket(self, packet):
        interface,timestampH,timestampL,capturedlen,originallen = struct.unpack_from('=LLLLL', packet)
        timestamp = ((timestampH<<32) + timestampL) * 10**-6
        packet = packet[20:20+originallen]
        if interface >= len(self.interfaces):
            self.error = "unknown interface"
            return
        if self.interfaces[interface] != 1 or capturedlen != originallen:
            return # not an Ethernet packet or truncated packet
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
            return Packet(timestamp, srcip, dstip, esp=esp, tcp=dict(srcport=srcport, dstport=dstport), data=data)
        elif protocol == 17:
            srcport,dstport = struct.unpack_from('!2H', packet)
            data = packet[8:]
            return Packet(timestamp, srcip, dstip, esp=esp, udp=dict(srcport=srcport, dstport=dstport), data=data)

    def decodeoptions(self, options):
        while True:
            if len(options) < 4:
                return
            code,length = struct.unpack_from('=HH', options)
            if len(options) < 4+length:
                return
            value = options[4:4+length]
            options = options[4+length:]
            yield code,value
