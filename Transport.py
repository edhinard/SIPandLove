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
log = logging.getLogger('Transport')

from . import Message
from . import Header


errorcb = None

# http://code.activestate.com/recipes/439094
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('ascii'))
    )[20:24])


class Transport(multiprocessing.Process):
    def __init__(self, localiporinterface, localport=5060, tcp_only=False):
        if not '.' in localiporinterface:
            self.localip = get_ip_address(localiporinterface)
        else:
            self.localip = localiporinterface
        self.localport = localport
        self.tcp_only = tcp_only
        self.error = ErrorListener.newlistener(self.localip)
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
        if self.tcp_only:
            protocol = "TCP"
        else:
            protocol = "TCP+UDP"
        return "{}/{}:{}".format(protocol, self.localip, self.localport)

    def send(self, message, addr=(None,5060), protocol=None):
        if not isinstance(message, Message.SIPMessage):
            raise TypeError("expecting SIPMessage subclass as message")
        if isinstance(addr, (list,tuple)):
            if len(addr) != 2:
                raise Exception("expecting 2 values in addr, got {!r}".format(addr))
            ip,port = addr
        else:
            ip = addr
            port = 5060

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

        log.info("--> %s/%s:%d\n%s-", protocol, ip, port, message)
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
                log.info("<-- %s/%s:%d\n%s-", protocol, ip, port, message)
                return message
        return None
                
    def run(self):
        maintcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        maintcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            maintcp.bind((self.localip, self.localport))
            maintcp.listen()
        except OSError as err:
            exc = Exception("cannot bind TCP socket to {}:{}. errno={}".format(self.localip, self.localport, errno.errorcode[err.errno]))
            self.childpipe.send(exc)
            return

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                        self.error.pipein.send((str(e), remoteaddr, packet))
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

class ErrorListener(threading.Thread):
    listeners = {}
    lock = threading.Lock()
    warningraw = False

    @staticmethod
    def newlistener(ip):
        with ErrorListener.lock:
            if not ip in ErrorListener.listeners:
                ErrorListener.listeners[ip] = ErrorListener(ip)
            return ErrorListener.listeners[ip]
    
    def __init__(self, ip):
        self.pipeout,self.pipein = multiprocessing.Pipe(duplex=False)
        try:
            self.rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            self.rawsock.bind((ip,0))
        except:
            self.rawsock = None
            if not ErrorListener.warningraw:
                ErrorListener.warningraw = True
                log.warning("Cannot open raw socket for ICMP. Administrator privilege needed to do so")
        threading.Thread.__init__(self, daemon=True)
        self.start()

    def run(self):
        global errorcb
        if self.rawsock:
            waitto = (self.rawsock,self.pipeout)
        else:
            waitto = (self.pipeout,)
        while True:
            ready = multiprocessing.connection.wait(waitto)[0]

            # Partially parse ICMP packet received on raw socket and call error callback
            #  -check it is a type,code combination that should be transmitted to TU
            #  -check it holds UDP or TCP
            #  -parse destination IP and port
            #  -parse SIP message
            if self.rawsock == ready:
                packet,addr = self.rawsock.recvfrom(65536)
                if len(packet) < 20+8+20+8: # IP | ICMP | IP | ...
                    continue
                ipproto, = struct.unpack_from('B', packet, 9)
                if ipproto != 1: # ICMP
                    continue
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
                        continue
                elif icmptype == 12:
                    err = "Parameter Problem"
                else:
                    continue
                ip2proto, = struct.unpack_from('B', packet, 20+8+9)
                if ip2proto == 6: # TCP
                    message = packet[20+8+20+20:]
                elif ip2proto == 17: # UDP
                    message = packet[20+8+20+8:]
                else:
                    continue
                dstip = '.'.join((str(b) for b in struct.unpack_from('4B', packet, 20+8+16)))
                dstport, = struct.unpack_from('!H', packet, 20+8+20+2)
                message = Message.SIPMessage.frombytes(message)
                if message:
                    log.info("<-- ERR/%s:%d %s\n%s-", dstip, dstport, err, message)
                    if errorcb:
                        with ErrorListener.lock:
                            errorcb(err, (dstip,dstport), message)

            # Unqueue error from the pipe and call error callback
            elif self.pipeout == ready:
                err,addr,message = self.pipeout.recv()
                message = Message.SIPMessage.frombytes(message)
                if message:
                    log.info("<-- ERR/%s:%d %s\n%s-", *addr, err, message)
                    if errorcb:
                        with ErrorListener.lock:
                            errorcb(err, addr, message)

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
