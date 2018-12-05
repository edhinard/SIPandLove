#! /usr/bin/env python3
# coding: utf-8


import sys
import os
import subprocess
import socket
import multiprocessing
import selectors
import ctypes
import ipaddress
import errno
import ctypes.util
import random
import string
_setns = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True).setns


ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806

PROTOCOLS = {}
try:
    with open('/etc/protocols', 'r') as f:
        for line in f:
            chunks = line.split('#',1)[0].strip().split()
            try:
                name = chunks.pop(0)
                proto = int(chunks.pop(0))
            except:
                continue
            PROTOCOLS[proto] = name
except:
    raise

class MacAddr:
    def __init__(self, addr):
        try:
            if isinstance(addr, bytes):
                self.packed = addr
            elif isinstance(addr, int):
                self.packed = addr.to_bytes(6, 'big')
            elif isinstance(addr, str):
                ints = [int(x,16) for x in addr.split(':')]
                self.packed = [i for i in ints if i < 256]
            else:
                raise Exception()
            if len(self.packed) != 6:
                raise Exception()
        except:
            raise ValueError("{} does not appear to be a MAC address".format(addr)) from None
    def __str__(self):
        s = self.packed.hex()
        return ':'.join([x+y for x,y in zip(s[::2],s[1::2])])
    def __eq__(self, other):
        if isinstance(other, MacAddr):
            other = other.packed
        return self.packed == other

class Ether(ctypes.BigEndianStructure):
    _fields_ = (
        ('_dst', ctypes.c_byte * 6),
        ('_src', ctypes.c_byte * 6),
        ('_typ', ctypes.c_byte * 2),
    )
    def getdst(self):
        return MacAddr(bytes(self._dst))
    def setdst(self, value):
        if isinstance(value, MacAddr):
            value = value.packed
        self._dst = (ctypes.c_byte * 6)(*value)
    destination = property(getdst, setdst)
    def getsrc(self):
        return MacAddr(bytes(self._src))
    def setsrc(self, value):
        if isinstance(value, MacAddr):
            value = value.packed
        self._src = (ctypes.c_byte * 6)(*value)
    source = property(getsrc, setsrc)
    def gettyp(self):
        return int.from_bytes(bytes(self._typ), 'big')
    def settyp(self, value):
        self._typ = (ctypes.c_byte * 2)(*value.to_bytes(2, 'big'))
    type = property(gettyp, settyp)

class IPv4(ctypes.BigEndianStructure):
    _fields_ = (
        ('version', ctypes.c_byte, 4),
        ('ihl', ctypes.c_byte, 4),
        ('dscp', ctypes.c_byte, 6),
        ('ecn', ctypes.c_byte, 2),
        ('length', ctypes.c_uint16),
        ('identification', ctypes.c_uint16),
        ('flags', ctypes.c_uint16, 3),
        ('offset', ctypes.c_uint16, 13),
        ('ttl', ctypes.c_uint8),
        ('protocol', ctypes.c_uint8),
        ('checksum', ctypes.c_uint16),
        ('_src', ctypes.c_byte * 4),
        ('_dst', ctypes.c_byte * 4),
    )
    def getsrc(self):
        return ipaddress.IPv4Address(bytes(self._src))
    def setsrc(self, value):
        if isinstance(value, ipaddress.IPv4Address):
            value = value.packed
        self._src = (ctypes.c_byte * 4)(*value)
    src = property(getsrc, setsrc)
    def getdst(self):
        return ipaddress.IPv4Address(bytes(self._dst))
    def setdst(self, value):
        if isinstance(value, ipaddress.IPv4Address):
            value = value.packed
        self._dst = (ctypes.c_byte * 4)(*value)
    dst = property(getdst, setdst)

class ARP(ctypes.BigEndianStructure):
    _fields_ = (
        ('hwtype', ctypes.c_uint16),
        ('ptype', ctypes.c_uint16),
        ('hwlen', ctypes.c_uint8),
        ('plen', ctypes.c_uint8),
        ('operation', ctypes.c_uint16),
        ('_hwsrc', ctypes.c_byte * 6),
        ('_psrc', ctypes.c_byte * 4),
        ('_hwdst', ctypes.c_byte * 6),
        ('_pdst', ctypes.c_byte * 4),
    )
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if hwtype != 0x0001 or ptype != ETH_P_IP or hwlen != 6 or plen != 4:
            raise Exception("Not an ETH/IPv4 ARP packet")
    def gethwsrc(self):
        return MacAddr(bytes(self._hwsrc))
    def sethwsrc(self, value):
        if isinstance(value, MacAddr):
            value = value.packed
        self._hwsrc = (ctypes.c_byte * 6)(*value)
    hwsrc = property(gethwsrc, sethwsrc)
    def gethwdst(self):
        return MacAddr(bytes(self._hwdst))
    def sethwdst(self, value):
        if isinstance(value, MacAddr):
            value = value.packed
        self._hwdst = (ctypes.c_byte * 6)(*value)
    hwdst = property(gethwdst, sethwdst)
    def getpsrc(self):
        return ipaddress.IPv4Address(bytes(self._psrc))
    def setpsrc(self, value):
        if isinstance(value, ipaddress.IPv4Address):
            value = value.packed
        self._psrc = (ctypes.c_byte * 4)(*value)
    psrc = property(getpsrc, setpsrc)
    def getpdst(self):
        return ipaddress.IPv4Address(bytes(self._pdst))
    def setpdst(self, value):
        if isinstance(value, ipaddress.IPv4Address):
            value = value.packed
        self._pdst = (ctypes.c_byte * 4)(*value)
    pdst = property(getpdst, setpdst)

class UDP(ctypes.BigEndianStructure):
    _fields_ = (
        ('source', ctypes.c_uint16),
        ('destination', ctypes.c_uint16),
        ('length', ctypes.c_uint16),
        ('checksum', ctypes.c_uint16),
    )

class TCP(ctypes.BigEndianStructure):
    _fields_ = (
        ('source', ctypes.c_uint16),
        ('destination', ctypes.c_uint16),
        ('sequence', ctypes.c_uint32),
        ('ack', ctypes.c_uint32),        
        ('offset', ctypes.c_uint8, 4),
        ('reserved', ctypes.c_byte, 3),
        ('ns', ctypes.c_byte, 1),
        ('cwr', ctypes.c_byte, 1),
        ('ece', ctypes.c_byte, 1),
        ('urg', ctypes.c_byte, 1),
        ('ack', ctypes.c_byte, 1),
        ('psh', ctypes.c_byte, 1),
        ('rst', ctypes.c_byte, 1),
        ('syn', ctypes.c_byte, 1),
        ('fin', ctypes.c_byte, 1),
        ('window', ctypes.c_uint16),
        ('checksum', ctypes.c_uint16),
        ('pointer', ctypes.c_uint16),
    )

vowels = 'aeiouyAEIOUY'
consonants = ''.join(set(string.ascii_lowercase) - set(vowels))
CV = tuple([c+v for c in consonants for v in vowels])
class UDPTunnel(multiprocessing.Process):
    """
Object that implements an IP tunnel. It is used like this:

  with UDPTunnel((Aip, Aport), (Bip, Bport)) as tunnelend:
    print(tunnelend.localif)
    tunnelend.addip(newip)
    ...

Code inside the with block runs in an isolated network namespace with a single network interface
called .localif. Any IP packets sent from this interface will be enclosed in a UDP packet from
Aport to Bport and routed from local Aip to remote Bip. We can imagine at the other end
of the tunnel another script like this:

  with UDPTunnel((Bip, Bport), (Aip, Aport)) as tunnelend:
    ...

The utility function addip() can be used to add new IP addresses to the network
interface in the isolated network namespace. And then any socket works as expected.


                 local ip:port             remote ip:port
                      |======= UDP tunnel =======|
      *-------------------------------------------------------
 local interface      |==========================|

    """
    def __init__(self, localtunnelend, remotetunnelend, verbose=False):
        self.localtunnelend = localtunnelend
        self.remotetunnelend = remotetunnelend
        self.verbose = verbose

        self.selfnsfile = None
        self.netnsfile = None
        self.localips = set()
        self.semaphore = multiprocessing.Semaphore(0)
        multiprocessing.Process.__init__(self, daemon=True)


    def system(self, command):
        cmd = command.replace('{', '{0.').format(self).split()
        if self.verbose:
            ns = "({})".format(self.ns) if self.netnsfile else "(-)        "
            print("{}$ {}".format(ns, ' '.join(cmd)))
        try:
            p = subprocess.run([a.strip('"') for a in cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception as e:
            print("{}--> {}".format(e.stdout.decode(errors='ignore'), e.returncode))
            raise

    def addip(self, localip):
        if localip in self.localips:
            raise Exception("address {} already exists".format(localip))
        self.localips.add(localip)
        self.system('ip address add dev {localif} ' + localip + '/32')

    def removeip(self, localip):
        if localip not in self.localips:
            raise Exception("unknown address {}".format(localip))
        self.localips.remove(localip)
        self.system('ip address del dev {localif} ' + localip + '/32')

    def __enter__(self):
        tag = random.choice(CV)+random.choice(CV)+random.choice(CV)
        self.ns = 'ns-{}'.format(tag)
        self.localif = 'loc-{}'.format(tag)
        self.remoteif = 'rem-{}'.format(tag)

        try:
            # create a network namespace and a veth pair of which one end is moved to the namespace
            self.system('ip netns add {ns}')
            self.system('ip link add {localif} type veth peer name {remoteif} noproxy')
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
            s.bind((self.localif, ETH_P_IP))
            self.localhwaddr = s.getsockname()[4]
            s.close()
            self.system('ip link set {localif} netns {ns}')

            # remote network configuration
            self.system('ip link set {remoteif} up')
            self.system('ip link set {remoteif} arp off')
            self.system('ethtool --offload {remoteif} rx off  tx off')

            # open socket at both end of simulated tunnel
            self.tunnelsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.tunnelsocket.bind(self.localtunnelend)
            except OSError as err:
                raise Exception("Cannot bind to {} - {}".format(self.localtunnelend, err)) from None
            os.set_inheritable(self.tunnelsocket.fileno(), True)

            self.rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.rawsocket.bind((self.remoteif, ETH_P_ALL))
            self.rawhwaddr = self.rawsocket.getsockname()[4]

            self.start()
            self.semaphore.acquire()

            # enter network namespace
            try:
                self.netnsfile = open('/var/run/netns/{}'.format(self.ns), 'rb')
            except FileNotFoundError:
                raise Exception("No such network namespace {!r}".format(self.ns)) from None
            self.selfnsfile = open('/proc/self/ns/net', 'rb')
            if _setns(self.netnsfile.fileno(), 0) == -1:
                e = ctypes.get_errno()
                self.netnsfile.close()
                self.selfnsfile.close()
                raise OSError(e, errno.errorcode[e])

            # local network configuration
            self.system('ip link set {localif} up')
            self.system('ip route add default dev {localif}')
            self.system('ethtool --offload {localif} rx off  tx off')

        except:
            self.cleanup()
            raise
            
        return self

    def __exit__(self, type, value, tb):
        self.cleanup()

    def cleanup(self):
        if self.selfnsfile:
            _setns(self.selfnsfile.fileno(), 0)
            self.netnsfile.close()
            self.selfnsfile.close()
        try:
            self.system('ip link delete {remoteif}')
            self.system('ip netns delete {ns}')
        except:
            pass

    def run(self):
        sel = selectors.DefaultSelector()
        sel.register(self.rawsocket, selectors.EVENT_READ)
        sel.register(self.tunnelsocket, selectors.EVENT_READ)
        self.semaphore.release()
        while True:
            try:
                for key,mask in sel.select():
                    if key.fileobj == self.tunnelsocket:
                        p,a = self.tunnelsocket.recvfrom(1000)
                        if a != self.remotetunnelend:
                            continue
                        if self.verbose:
                            print("local<-- IP<--remote")
                            self.printIP(p)
                        q = bytearray(ctypes.sizeof(Ether) + len(p))
                        q[ctypes.sizeof(Ether):] = p
                        e = Ether.from_buffer(q)
                        e.source,e.destination = self.rawhwaddr,self.localhwaddr
                        e.type = ETH_P_IP
                        self.rawsocket.sendto(bytes(q), (self.remoteif, ETH_P_IP, 0, 0, self.localhwaddr))

                    elif key.fileobj == self.rawsocket:
                        p,a = self.rawsocket.recvfrom(1000)

                        if a[1] == ETH_P_ARP:
                            q = bytearray(p)
                            e = Ether.from_buffer(q)
                            try:
                                arp = ARP.from_buffer(q, ctypes.sizeof(Ether))
                            except:
                                continue

                            if arp.operation == 1:
                                if arp.hwsrc == self.localhwaddr:
                                    if self.verbose:
                                        print("local-->ARP\n        Who has {}? Tell {}".format(arp.pdst, arp.psrc))
                                    e.source,e.destination = self.rawhwaddr,e.source
                                    arp.operation = 2
                                    arp.hwsrc,arp.hwdst = self.rawhwaddr,arp.hwsrc
                                    arp.psrc,arp.pdst = arp.pdst,arp.psrc
                                    if self.verbose:
                                        print("local<--ARP\n        {} is at {}".format(arp.psrc, arp.hwsrc))
                                    self.rawsocket.sendto(q, (self.remoteif, ETH_P_ARP, 0, 0, self.rawhwaddr))

                        if a[1] == ETH_P_IP and a[2] == socket.PACKET_HOST:
                            if self.verbose:
                                print("local--> IP-->remote")
                                self.printIP(p[ctypes.sizeof(Ether):])
                            self.tunnelsocket.sendto(p[ctypes.sizeof(Ether):], self.remotetunnelend)
            except OSError:
                break

    def printIP(self, p):
        i = IPv4.from_buffer_copy(p)
        ippayloadlen = len(p) - ctypes.sizeof(IPv4)
        if i.protocol == 6:
            t = TCP.from_buffer_copy(p, ctypes.sizeof(IPv4))
            flags = ', '.join((flag for flag in ('syn','ack','fin','psh','rst','urg') if getattr(t, flag)))
            length = ippayloadlen - 4*t.offset
            disp = "tcp {} -> {} [{}] Len={}".format(t.source, t.destination, flags, length)
        elif i.protocol == 17:
            u = UDP.from_buffer_copy(p, ctypes.sizeof(IPv4))
            length = ippayloadlen - ctypes.sizeof(UDP)
            disp = "udp {} -> {} Len={}".format(u.source, u.destination, length)
        else:
            proto = PROTOCOLS.get(i.protocol) or "proto={}".format(i.protocol)
            length = len(p) - ctypes.sizeof(IPv4)
            disp = "{} Len={}".format(proto, length)
        print("         {} -> {} Len={} \ {}".format(i.src, i.dst, ippayloadlen, disp))
