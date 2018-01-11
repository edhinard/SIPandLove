#! /usr/bin/python3
# coding: utf-8

import socket
import sys
import threading
import multiprocessing
import multiprocessing.connection
import time
import socket
import fcntl
import struct
import logging
import errno
import weakref
log = logging.getLogger('Transport')

from . import Message
from . import Header


# http://code.activestate.com/recipes/439094
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('ascii'))
    )[20:24])


class Transport(multiprocessing.Process):
    instances = weakref.WeakSet()
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        Transport.instances.add(instance)
        return instance

    def __init__(self, localiporinterface, localport=None, tcp_only=False):
        if ':' in localiporinterface:
            localiporinterface,port = localiporinterface.split(':', 1)
            port = int(port)
            if localport is not None and localport != port:
                raise Exception("two conflicting values for port between {!r}:{} and localport={}".format(localiporinterface, port, localport))
            localport = port
        if not '.' in localiporinterface:
            self.localip = get_ip_address(localiporinterface)
        else:
            self.localip = localiporinterface
        self.localport = localport or 5060
        self.tcp_only = tcp_only
        self.errorcb = None
        self.pipe,self.childpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self, daemon=True)
        self.start()
        ret = self.pipe.recv()
        if ret is None:
            log.debug("%s starting process %d", self, self.pid)
        else:
            log.error(ret)
            log.error("%s process not started", self)
            raise ret

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    def send(self, message, addr=None, protocol=None):
        if not isinstance(message, Message.SIPMessage):
            raise TypeError("expecting SIPMessage subclass as message")
        addr = addr or (None,5060)
        if isinstance(addr, (list,tuple)):
            if len(addr) != 2:
                raise Exception("expecting 2 values in addr, got {!r}".format(addr))
            ip,port = addr
        elif isinstance(addr, str):
            if ':' in addr:
                ip,port = addr.split(':', 1)
                port = int(port)
            else:
                ip = addr
                port = 5060
        else:
            raise Exception("expecting a 2uple or a string for addr, got {!r}".format(addr))

        via = message.getheader('via')
        if isinstance(message, Message.SIPRequest):
            if ip is None:
                raise Exception("missing address")

            protocol = 'TCP' if self.tcp_only else 'UDP'
            if via:
                if via.protocol == '???':
                    via.protocol = protocol
                if via.host == '0.0.0.0':
                    via.host = self.localip
                if via.port == None and self.localport != 5060:
                    via.port = self.localport

        elif isinstance(message, Message.SIPResponse):
            if via:
                protocol = via.protocol
            else:
                protocol = 'TCP' if self.tcp_only else 'UDP'
            if ip is None:
                if via:
                    if protocol == 'TCP':
                        ip = via.host
                    else:
                        ip = via.params.get('received', via.host)
            if ip is None:
                raise Exception("no address where to send response")
            if via:
                if protocol == 'TCP':
                    port = via.port or 5060
                else:
                    port = via.params.get('rport', via.port) or 5060

        if (protocol == 'TCP' or len(message.body)) and not message.getheader('l'):
            message.addheaders(Header.Content_Length(length=len(message.body)))

        log.info("%s --%s-> %s:%d\n%s", self, protocol, ip, port, message)
        self.pipe.send((protocol, (ip, port), message.tobytes()))

    def recv(self, timeout=None):
        if self.pipe.poll(timeout):
            protocol,(ip,port),message = self.pipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message:
                if isinstance(message, Message.SIPRequest):
                    via = message.getheader('via')
                    if via:
                        if via.host != ip:
                            via.params['received'] = ip
                        if 'rport' in via.params:
                            via.params['received'] = ip
                            via.params['rport'] = port
                log.info("%s <-%s-- %s:%d\n%s", self, protocol, ip, port, message)
                return message
        return None
                
    def run(self):
        maintcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            maintcp.bind((self.localip, self.localport))
            maintcp.listen()
        except OSError as err:
            exc = Exception("cannot bind TCP socket to {}:{}. errno={}".format(self.localip, self.localport, errno.errorcode[err.errno]))
            self.childpipe.send(exc)
            return

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.bind((self.localip, self.localport))
        except OSError as err:
            exc = Exception("cannot bind UDP socket to {}:{}. errno={}".format(self.localip, self.localport, errno.errorcode[err.errno]))
            self.childpipe.send(exc)
            return

        self.childpipe.send(None)
        tcpsockets = ServiceSockets()
        while True:
            for obj in multiprocessing.connection.wait([self.childpipe, maintcp, udp] + list(tcpsockets), 1):
                # Packet comming from upper layer --> send to remote address
                if obj == self.childpipe:
                    protocol,remoteaddr,packet = self.childpipe.recv()
                    try:
                        if protocol == 'TCP':
                            tcpsockets.sendto(packet, remoteaddr)
                        elif protocol == 'UDP':
                            udp.sendto(packet, remoteaddr)
                        err = None
                    except Exception as e:
                        global errordispatcher
                        errordispatcher.pipein.send((self.localip, self.localport, *remoteaddr, str(e), packet))
                        continue

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif obj == maintcp:
                    tcpsockets.add(*maintcp.accept())

                # Incomming UDP packet --> decode and send to upper layer
                elif obj == udp:
                    packet,remoteaddr = udp.recvfrom(65536)
                    decodeinfo = Message.SIPMessage.predecode(packet)
                    # Discard inconsistent messages
                    if decodeinfo.status != 'OK':
                        continue
                    
                    self.childpipe.send(('UDP',remoteaddr,packet[decodeinfo.istart:decodeinfo.iend]))

                # Incomming TCP buffer --> assemble with previous buffer(done by ServiceSocket class), decode and send to upper layer
                else:
                    assert(obj in tcpsockets)
                    buf,remoteaddr = tcpsockets.recvfrom(obj)
                    while True:
                        decodeinfo = Message.SIPMessage.predecode(buf)

                        # Erroneous messages or messages missing a Content-Length make the stream desynchronized
                        if decodeinfo.status == 'ERROR' or (decodeinfo.status == 'OK' and not decodeinfo.framing):
                            tcpsockets.delete(obj)
                            break

                        # Ignore inconsistent messages, wait for the rest of the buffer
                        if decodeinfo.status != 'OK':
                            break

                        self.childpipe.send(('TCP',remoteaddr,buf[decodeinfo.istart:decodeinfo.iend]))
                        del buf[:decodeinfo.iend]
                            
            tcpsockets.cleanup()

class ServiceSockets:
    TIMEOUT = 32.
    
    def __init__(self):
        self.bysock = {}
        self.byaddr = {}

    def add(self, sock, addr):
        newitem = (sock, addr, bytearray(), [time.monotonic()])
        self.bysock[sock] = newitem
        self.byaddr[addr] = newitem

    def __iter__(self):
        for sock in self.bysock.keys():
            yield sock

    def __contains__(self, sock):
        return sock in self.bysock

    def sendto(self, packet, addr):
        if addr not in self.byaddr:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(.5)
            sock.connect(addr)
            self.add(sock, addr)
        sock,addr,buf,lasttime = self.byaddr[addr]
        lasttime[0] = time.monotonic()
        sock.send(packet)

    def recvfrom(self, sock):
        sock,addr,buf,lasttime = self.bysock[sock]
        lasttime[0] = time.monotonic()
        newbuf = sock.recv(8192)
        if not newbuf:
            self.delete(obj)
        buf += newbuf
        return buf,addr

    def delete(self, sock):
        sock,addr,buf,lasttime = self.bysock[sock]
        try:
            sock.close()
        except:
            pass
        del self.bysock[sock]
        del self.byaddr[addr]

    def cleanup(self):
        # TCP socket that are idle for more than 64*T1 sec are closed [18]
        currenttime = time.monotonic()
        for sock,(s,addr,buf,lasttime) in list(self.bysock.items()):
            if currenttime - lasttime[0] > self.TIMEOUT:
                self.delete(sock)

class ErrorDispatcher(threading.Thread):
    def __init__(self):
        self.pipeout1,icmppipe = multiprocessing.Pipe(duplex=False)
        self.pipeout2,self.pipein = multiprocessing.Pipe(duplex=False)
        self.icmp = ICMPProcess(icmppipe)
        super().__init__(daemon=True)
        self.start()

    def run(self):
        while True:
            for pipe in multiprocessing.connection.wait((self.pipeout1, self.pipeout2)):
                srcip, srcport, dstip, dstport, err, data = pipe.recv()
                message = Message.SIPMessage.frombytes(data)
                if message:
                    for transport in Transport.instances:
                        if transport.localip == srcip and transport.localport == srcport:
                            log.info("%s <-ERR-- %s:%d %s\n%s", transport, dstip, dstport, err, message)
                            if transport.errorcb:
                                transport.errorcb(message, err)
                            break

class ICMPProcess(multiprocessing.Process):
    def __init__(self, pipe):
        super().__init__(daemon=True)
        self.pipe = pipe
        self.start()

    def run(self):
        try:
            rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except:
            log.warning("Cannot open raw socket for ICMP. Administrator privilege needed to do so")
            return

        while True:
            # decode ICMP packet seen on socket
            packet,addr = rawsock.recvfrom(65536)
            if len(packet) < 20+8+20+8: # IP | ICMP | IP | ...
                continue # too short
            ipproto, = struct.unpack_from('B', packet, 9)
            if ipproto != 1: # ICMP
                continue # not ICMP
            icmptype, icmpcode = struct.unpack_from('2b', packet, 20)
            if icmptype == 3: # Destination Unreachable
                if icmpcode == 0:
                    err = "Network Unreachable"
                elif icmpcode == 1:
                    err = "Host Unreachable"
                elif icmpcode == 2:
                    err = "Protocol Unreachable"
                elif icmpcode == 3:
                    err = "Port Unreachable"
                else:
                    continue # ignored code
            elif icmptype == 12:
                err = "Parameter Problem"
            else:
                continue # ignored type
            ip2proto, = struct.unpack_from('B', packet, 20+8+9)
            if ip2proto == 6: # TCP
                data = packet[20+8+20+20:]
            elif ip2proto == 17: # UDP
                data = packet[20+8+20+8:]
            else:
                continue # ignored transport
            message = Message.SIPMessage.frombytes(data)
            if not message:
                continue # no message

            # send message in ICMP to ErrorDispatcher
            srcip = '.'.join((str(b) for b in struct.unpack_from('4B', packet, 20+8+12)))
            dstip = '.'.join((str(b) for b in struct.unpack_from('4B', packet, 20+8+16)))
            dstport, = struct.unpack_from('!H', packet, 20+8+20+2)
            srcport, = struct.unpack_from('!H', packet, 20+8+20+0)
            self.pipe.send((srcip, srcport, dstip, dstport, err, data))

errordispatcher = ErrorDispatcher()


if __name__ == '__main__':
    import snl
    snl.loggers['Transport'].setLevel('INFO')

    t = snl.Transport('eno1', localport=5061, tcp_only=True)
    t.send(snl.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu'),
           ('194.2.137.40',5060)
    )
    t.send(snl.REGISTER('sip:osk.nkims.eu'), '127.0.0.1')
    t.recv(3)
    t.recv(3)
