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
import atexit
import signal
log = logging.getLogger('Transport')

from . import Message
from . import Header
from . import Security


# http://code.activestate.com/recipes/439094
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('ascii'))
    )[20:24])

@atexit.register
def cleanup():
    for transport in Transport.instances:
        transport.stop()

def splitaddr(addr):
    addr = addr or (None,None)
    if isinstance(addr, str):
        if ':' in addr:
            ip,port = addr.split(':', 1)
        else:
            ip = addr
            port = None
    elif isinstance(addr, (list,tuple)):
        if len(addr) != 2:
            raise Exception("expecting 2 values in addr ({!r})".format(addr))
        ip,port = addr
    else:
        raise Exception("addr should be a 2uple or a string not {!r}".format(addr))
    try:
        if port is not None:
            port = int(port)
    except:
        raise Exception("port number in addr ({!r}) should be None or an int".format(port))
    return ip,port

class Transport(multiprocessing.Process):
    instances = weakref.WeakSet()
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        Transport.instances.add(instance)
        return instance

    def __init__(self, *, listenpoint, protocol='UDP+TCP', errorcb=None):
        localiporinterface,self.localport = splitaddr(listenpoint)
        if not '.' in localiporinterface:
            try:
                self.localip = get_ip_address(localiporinterface)
            except Exception as e:
                log.error("%s %r", e, localiporinterface)
                raise
        else:
            self.localip = localiporinterface

        self.protocol = protocol.upper()
        if not self.protocol in ('UDP', 'TCP', 'TLS', 'UDP+TCP'):
            raise Exception("bad value for protocol transport: {}".format(protocol))
        self.errorcb = errorcb
        if not self.localport:
            if self.protocol == 'TLS':
                self.localport = 5061
            else:
                self.localport = 5060
        self.messagepipe,self.childmessagepipe = multiprocessing.Pipe()
        self.commandpipe,self.childcommandpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self)
        self.start()
        log.info("%s starting process %d", self, self.pid)

        try:
            if 'UDP' in self.protocol:
                self.mainudp = self.openmainUDP()
                log.info("UDP listening on %s:%d (fd=%d)", self.localip, self.localport, self.mainudp)
            if 'TCP' in self.protocol:
                fd = self.openmainTCP()
                log.info("TCP listening on %s:%d (fd=%d)", self.localip, self.localport, fd)
            if self.protocol == 'TLS':
                pass
        except Exception as e:
            log.error("%s - %s", self, e)
            raise Exception("Transport initialization error") from None

        self.localsa = self.remotesa = None
        self.establishedSA = False

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    def send(self, message, addr=None):
        assert isinstance(message, Message.SIPMessage)

        if message.contacturi:
            if self.protocol == 'UDP+TCP':
                message.contacturi.params.pop('transport', None)
            else:
                message.contacturi.params['transport'] = self.protocol

        if isinstance(message, Message.SIPRequest):
            assert addr
            dstip,dstport = splitaddr(addr)
            protocol = self.protocol
            if protocol == 'TLS':
                dstport = dstport or 5061
                message.length = len(message.body)
                pass
            else:
                dstport = dstport or 5060
                if protocol == 'UDP+TCP':
                    if len(message.tobytes()) > 1300:
                        protocol = 'TCP'
                    else:
                        protocol = 'UDP'
                if protocol == 'TCP':
                    message.length = len(message.body)

                if self.establishedSA:
                    if protocol == 'TCP':
                        fd = self.localsa['tcpc']
                        srcport = self.localsa['portc']
                        viaport = self.localsa['ports']
                        addr = (dstip, dstport)
                    elif protocol == 'UDP':
                        fd = self.localsa['udpc']
                        srcport = self.localsa['portc']
                        viaport = self.localsa['ports']
                        addr = (dstip, dstport)
                    protocol = '{}/ESP'.format(protocol)
                else:
                    if protocol == 'TCP':
                        fd,srcport = self.gettcpsocket(dstip, dstport)
                        viaport = self.localport
                        addr = (dstip, dstport)
                    elif protocol == 'UDP':
                        fd = self.mainudp
                        viaport = srcport = self.localport
                        addr = (dstip, dstport)

                via = message.header('via')
                if via:
                    via.protocol = protocol[:3]
                    via.host = self.localip
                    via.port = viaport if viaport!=5060 else None

        elif isinstance(message, Message.SIPResponse):
            assert addr is None
            via = message.header('via')
            if via:
                protocol = via.protocol
                dstip = via.params.get('received', via.host)
                dstport = via.params.get('rport', via.port)
            else:
                raise Exception("no address where to send response")

            if self.protocol == 'TLS':
                dstport = dstport or 5061
                message.length = len(message.body)
                pass
            else:
                dstport = dstport or 5060
                if protocol == 'TCP':
                    message.length = len(message.body)

                if self.establishedSA:
                    if protocol == 'TCP':
                        fd = self.localsa['tcps']
                        srcport = self.localsa['ports']
                        addr = (dstip, dstport)
                    elif protocol == 'UDP':
                        fd = self.localsa['udpc']
                        srcport = self.localsa['portc']
                        addr = (dstip, dstport)
                    protocol = '{}/ESP'.format(protocol)
                else:
                    if protocol == 'TCP':
                        fd,srcport = self.gettcpsocket(dstip, dstport, message.fd)
                        addr = (dstip, dstport)
                    elif protocol == 'UDP':
                        fd = self.mainudp
                        srcport = self.localport
                        addr = (dstip, dstport)

        log.info("%s:%d --%s-> %s:%d (fd=%d)\n%s", self.localip, srcport, protocol, dstip, dstport, fd, message)
        self.messagepipe.send((fd, addr, message.tobytes()))

    def recv(self, timeout=None):
        if self.messagepipe.poll(timeout):
            fd,protocol,(srcip,srcport),dstport,message = self.messagepipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message is not None:
                message.fd = fd
                if isinstance(message, Message.SIPRequest):
                    via = message.header('via')
                    if via:
                        if via.host != srcip:
                            via.params['received'] = srcip
                        if 'rport' in via.params:
                            via.params['received'] = srcip
                            via.params['rport'] = srcport
                esp = ''
                if self.establishedSA and srcip == self.remotesa['ip'] and dstport in (self.localsa['portc'],self.localsa['ports']):
                    esp = '/ESP'
                log.info("%s:%s <-%s%s-- %s:%d (fd=%d)\n%s", self.localip, dstport, protocol, esp, srcip, srcport, fd, message)
                return message
        return None

    def command(self, *args):
        self.commandpipe.send(args)
        ret = self.commandpipe.recv()
        if isinstance(ret, Exception):
            raise ret
        return ret

    def stop(self):
        self.commandpipe.send(('stop',))

    def openmainUDP(self):
        fd = self.command('main', 'udp')
        return fd

    def openmainTCP(self):
        fd = self.command('main', 'tcp')
        return fd

    def gettcpsocket(self, remoteip, remoteport, fd=None):
        fd,localport = self.command('gettcp', (remoteip, remoteport), fd)
        return fd, localport

    def prepareSA(self, remoteip):
        self.localsa = self.command('sa', 'prepare', self.localip, remoteip)
        sa = {k:self.localsa[k] for k in ('spis', 'spic', 'ports', 'portc')}
        return sa

    def establishSA(self, **kwargs):
        self.remotesa  = self.command('sa', 'establish', kwargs)
        self.establishedSA = True

    def terminateSA(self, **kwargs):
        self.command('sa', 'terminate', kwargs)
        self.establishedSA = False
        self.localsa = self.remotesa = None

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        localaddr = (self.localip, self.localport)
        tcplisteningsocket = None
        servicesockets = ServiceSockets()
        sa = None
        while True:
            sockets = [self.childcommandpipe, self.childmessagepipe] + \
                      ([tcplisteningsocket] if tcplisteningsocket else []) + \
                      servicesockets
            for obj in multiprocessing.connection.wait(sockets, 1):
                # Command comming from main process
                if obj == self.childcommandpipe:
                    command = self.childcommandpipe.recv()
                    if command[0] == 'stop':
                        if sa:
                            sa.terminate()
                        self.childcommandpipe.send(None)
                        return
                    elif command[0] == 'main':
                        layer4, = command[1:]
                        if layer4 == 'tcp':
                            try:
                                tcplisteningsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                tcplisteningsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                tcplisteningsocket.bind(localaddr)
                                tcplisteningsocket.listen()
                                self.childcommandpipe.send(tcplisteningsocket.fileno())
                            except OSError as err:
                                exc = Exception("cannot bind TCP socket to {}:{}. errno={}".format(*localaddr, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                        elif layer4 == 'udp':
                            try:
                                mainudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                mainudp.bind(localaddr)
                                servicesockets.new(mainudp)
                                self.childcommandpipe.send(mainudp.fileno())
                            except OSError as err:
                                exc = Exception("cannot bind UDP socket to {}:{}. errno={}".format(*localaddr, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                    elif command[0] == 'gettcp':
                        remoteaddr,fd = command[1:]
                        for sock in servicesockets:
                            if sock.tcp and (sock.fd==fd or sock.remoteaddr==remoteaddr):
                                break
                        else:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(.5)
                                sock.bind((self.localip, 0))
                                sock.connect(remoteaddr)
                                sock = servicesockets.new(sock)
                            except OSError as err:
                                exc = Exception("cannot connect to {}:{}. errno={}".format(*remoteaddr, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                                continue
                        self.childcommandpipe.send((sock.fd, sock.localport))
                    elif command[0] == 'sa':
                        try:
                            if command[1] == 'prepare':
                                sa = Security.SA(*command[2:])
                                local  = dict(ip=sa.local.ip,
                                              spis=sa.local.spis,  spic=sa.local.spic,
                                              ports=sa.local.ports,  portc=sa.local.portc,
                                              udpc=sa.local.udpc.fileno(), udps=sa.local.udps.fileno(),
                                              tcpc=sa.local.tcpc.fileno(), tcps=sa.local.tcps.fileno()
                                )
                                self.childcommandpipe.send(local)
                            elif command[1] == 'establish':
                                sa.finalize(**command[2])
                                sa.local.udps = servicesockets.new(sa.local.udps)
                                sa.local.udpc = servicesockets.new(sa.local.udpc)
                                remote = dict(ip=sa.remote.ip, spis=sa.remote.spis, spic=sa.remote.spic, ports=sa.remote.ports, portc=sa.remote.portc)
                                self.childcommandpipe.send(remote)
                            elif command[1] == 'terminate':
                                sa.terminate()
                                sa = None
                                self.childcommandpipe.send(None)
                        except Exception as exc:
                            self.childcommandpipe.send(exc)
                    else:
                        self.childcommandpipe.send(Exception("unknown command %s", ' '.join(command)))

                # Message comming from main process --> send to remote address
                elif obj == self.childmessagepipe:
                    fd,remoteaddr,packet = self.childmessagepipe.recv()
                    for sock in servicesockets:
                        if sock.fd==fd:
                            try:
                                sock.send(packet, remoteaddr)
                            except Exception as e:
                                dispatcherror(*localaddr, *remoteaddr, str(e), packet)
                            break
                    else:
                        dispatcherror(*localaddr, *remoteaddr, "cannot find socket with fd={}".format(fd), packet)

                # Incomming TCP connection --> new socket (will be read in the next result of poll)
                elif obj == tcplisteningsocket:
                    sock = obj.accept()[0]
                    servicesockets.new(sock)

                # Incomming packet --> decode and send to main process
                elif obj in servicesockets:
                    buf,remoteaddr = obj.recv()
                    if obj.udp:
                        decodeinfo = Message.SIPMessage.predecode(buf)

                        # Discard inconsistent messages
                        if decodeinfo.status != 'OK':
                            continue

                        messagebytes = buf[decodeinfo.istart:decodeinfo.iend]
                        self.childmessagepipe.send((obj.fd,'UDP',remoteaddr,obj.localport,messagebytes))

                    elif obj.tcp:
                        # assemble with previous buffer stored in TCPSocket
                        while True:
                            decodeinfo = Message.SIPMessage.predecode(buf)

                            # Erroneous messages or messages missing a Content-Length make the stream desynchronized
                            if decodeinfo.status == 'ERROR' or (decodeinfo.status == 'OK' and not decodeinfo.framing):
                                obj.close()
                                break

                            # Ignore inconsistent messages, wait for the rest of the buffer
                            if decodeinfo.status != 'OK':
                                break

                            messagebytes = buf[decodeinfo.istart:decodeinfo.iend]
                            self.childmessagepipe.send((obj.fd,'TCP',remoteaddr,obj.localport,messagebytes))
                            del buf[:decodeinfo.iend]

                servicesockets.cleanup()


class ServiceSocket:
    def __init__(self, sock, pool):
        self.__dict__.update(dict(
            sock = sock,
            pool = pool,
            fd = sock.fileno(),
            localport = sock.getsockname()[1],
            tcp = bool(sock.type & socket.SOCK_STREAM),
            udp = bool(sock.type & socket.SOCK_DGRAM)
        ))
        if self.tcp:
            self.__dict__.update(dict(
                remoteaddr = sock.getpeername(),
                buf = bytearray(),
                touchtime = time.monotonic()
            ))
    def __repr__(self):
        return repr(self.sock)
    def __getattr__(self, attr):
        value = self.__dict__.get(attr)
        if value is None:
            value = getattr(self.sock, attr)
        return value

    def send(self, packet, remoteaddr):
        if self.udp:
            self.sock.sendto(packet, remoteaddr)

        elif self.tcp:
            self.sock.sendall(packet)

    def recv(self):
        if self.udp:
            return self.sock.recvfrom(65536)

        # TCP stream
        newbuf = self.sock.recv(8192)
        if not newbuf:
            self.close()
        self.buf += newbuf
        self.touchtime = time.monotonic()
        return self.buf,self.remoteaddr

    def close(self):
        assert self in self.pool
        self.pool.remove(self)
        self.sock.close()

class ServiceSockets(list):
    TIMEOUT = 32.
    def new(self, sock):
        sock = ServiceSocket(sock, self)
        self.append(sock)
        return sock

    def cleanup(self):
        # TCP socket that are idle for more than 64*T1 sec are closed [18]
        currenttime = time.monotonic()
        for sock in self.copy():
            if sock.tcp and currenttime - sock.touchtime > self.TIMEOUT:
                sock.close()


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
                if pipe == self.pipeout1:
                    protocol = 'ICMP'
                else:
                    protocol = 'ERR-'
                message = Message.SIPMessage.frombytes(data)
                if message:
                    for transport in Transport.instances:
                        if transport.localip == srcip and transport.localport == srcport:
                            log.info("%s <-%s- %s:%d %s\n%s", transport, protocol, dstip, dstport, err, message)
                            if transport.errorcb:
                                transport.errorcb(message, err)
                            break
def dispatcherror(*args):
    global errordispatcher
    errordispatcher.pipein.send(args)


class ICMPProcess(multiprocessing.Process):
    def __init__(self, pipe):
        super().__init__(daemon=True)
        self.pipe = pipe
        self.start()

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except:
            log.warning("Cannot open raw socket for ICMP")
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
                payload = packet[20+8+20+20:]
            elif ip2proto == 17: # UDP
                payload = packet[20+8+20+8:]
            else:
                continue # ignored transport

            # send ICMP payload to ErrorDispatcher
            srcip = '.'.join((str(b) for b in struct.unpack_from('4B', packet, 20+8+12)))
            dstip = '.'.join((str(b) for b in struct.unpack_from('4B', packet, 20+8+16)))
            dstport, = struct.unpack_from('!H', packet, 20+8+20+2)
            srcport, = struct.unpack_from('!H', packet, 20+8+20+0)
            self.pipe.send((srcip, srcport, dstip, dstport, err, payload))

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
