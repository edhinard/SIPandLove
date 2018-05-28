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
                log.info("UDP listening on %s:%d", self.localip, self.localport)
            if 'TCP' in self.protocol:
                self.maintcp = self.openmainTCP()
                log.info("TCP listening on %s:%d", self.localip, self.localport)
            if self.protocol == 'TLS':
                pass
        except Exception as e:
            log.error("%s - %s", self, e)
            raise Exception("Transport initialization error") from None

            self.localsa = self.remotesa = None
            self.establishedSA = False

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    def getSA(self, *args):
        return False

    def send(self, message, addr=None):
        assert isinstance(message, Message.SIPMessage)

        if isinstance(message, Message.SIPRequest):
            assert addr
            dstip,dstport = splitaddr(addr)
            protocol = self.protocol
            if message.contacturi:
                if protocol == 'UDP+TCP':
                    message.contacturi.params.pop('transport', None)
                else:
                    message.contacturi.params['transport'] = protocol
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

                sa = self.getSA(dstip, dstport)
                if sa:
                    if protocol == 'TCP':
                        fd = sa.tcpc
                        srcport = sa.portc
                        addr = None
                    elif protocol == 'UDP':
                        fd = sa.udpc
                        srcport = sa.portc
                        addr = (dstip, dstport)
                    protocol = '{}/ESP'.format(protocol)
                else:
                    if protocol == 'TCP':
                        fd,srcport = self.getclienttcpsocket(dstip, dstport)
                        if fd == -1:
                            fd,srcport = self.newtcp(dstip, dstport)
                        addr = None
                    elif protocol == 'UDP':
                        fd = self.mainudp
                        srcport = self.localport
                        addr = (dstip, dstport)

                via = message.header('via')
                if via:
                    via.protocol = protocol[:3]
                    via.host = self.localip
                    via.port = srcport if srcport!=5060 else None

        elif isinstance(message, Message.SIPResponse):
            via = message.header('via')
            if via:
                protocol = via.protocol
                dstip = via.params.get('received', via.host)
                dstport = via.params.get('rport', via.port)
            elif addr:
                if self.protocol == 'UDP+TCP':
                    if len(message) > 1300:
                        protocol = 'TCP'
                    else:
                        protocol = 'UDP'
                else:
                    protocol = self.protocol
                dstip,dstport = splitaddr(addr)
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

                sa = self.getSA(dstip, dstport)
                if sa:
                    if protocol == 'TCP':
                        fd = sa.tcps
                        srcport = sa.ports
                        addr = None
                    elif protocol == 'UDP':
                        fd = sa.udps
                        srcport = sa.ports
                        addr = (dstip, dstport)
                    protocol = '{}/ESP'.format(protocol)
                else:
                    if protocol == 'TCP':
                        fd,srcport = self.getservertcpsocket(dstip, dstport)
                        if fd == -1:
                            raise Exception("{} is not an existing server address".format((dstip, dstport)))
                        addr = None
                    elif protocol == 'UDP':
                        fd = self.mainudp
                        srcport = self.localport
                        addr = (dstip, dstport)

        log.info("%s:%d --%s-> %s:%d\n%s", self.localip, srcport, protocol, dstip, dstport, message)
        self.messagepipe.send((fd, addr, message.tobytes()))

    def recv(self, timeout=None):
        if self.messagepipe.poll(timeout):
            protocol,(srcip,srcport),dstport,message = self.messagepipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message:
                if isinstance(message, Message.SIPRequest):
                    via = message.header('via')
                    if via:
                        if via.host != srcip:
                            via.params['received'] = srcip
                        if 'rport' in via.params:
                            via.params['received'] = srcip
                            via.params['rport'] = srcport
                esp = ''
#                if self.establishedSA and srcip == self.remotesa['ip'] and dstport in (self.localsa['portc'],self.localsa['ports']):
#                    esp = '/ESP'
                log.info("%s:%s <-%s%s-- %s:%d\n%s", self.localip, dstport, protocol, esp, srcip, srcport, message)
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

    def getclienttcpsocket(self, remoteip, remoteport):
        fd,localport = self.command('gettcp', 'client', (remoteip, remoteport))
        return fd, localport

    def newtcp(self, remoteip, remoteport):
        fd,localport = self.command('newtcp', (remoteip, remoteport))
        return fd, localport

    def getservertcpsocket(self, remoteip, remoteport):
        fd,localport = self.command('gettcp', 'server', (remoteip, remoteport))
        return fd, localport

    def prepareSA(self, remoteip):
        self.localsa = self.command('sa', 'prepare', self.localip, remoteip)
        self.localsa.pop('ip')
        return self.localsa

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
        maintcp = None
        mainudp = None
        clientsockets = ServiceSockets()
        serversockets = ServiceSockets()
        sa = None
        while True:
            sockets = [self.childcommandpipe, self.childmessagepipe, mainudp, maintcp] + \
                      list(clientsockets) + list(serversockets)
            sockets = list(filter(None, sockets))
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
                                maintcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                maintcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                maintcp.bind(localaddr)
                                maintcp.listen()
                                self.childcommandpipe.send(maintcp.fileno())
                            except OSError as err:
                                exc = Exception("cannot bind TCP socket to {}:{}. errno={}".format(*localaddr, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                        elif layer4 == 'udp':
                            try:
                                mainudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                mainudp.bind(localaddr)
                                self.childcommandpipe.send(mainudp.fileno())
                            except OSError as err:
                                exc = Exception("cannot bind UDP socket to {}:{}. errno={}".format(localip, localport, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                    elif command[0] == 'gettcp':
                        direction,remoteaddr = command[1:]
                        if direction == 'client':
                            sockets = clientsockets
                        elif direction == 'server':
                            sockets = serversockets
                        sock = sockets.get(remoteaddr)
                        if sock:
                            self.childcommandpipe.send((sock.fileno(), sock.getsockname()[1]))
                        else:
                            self.childcommandpipe.send((-1, -1))
                    elif command[0] == 'newtcp':
                        remoteaddr, = command[1:]
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(.5)
                            sock.bind((self.localip, 0))
                            sock.connect(remoteaddr)
                            clientsockets.add(sock, remoteaddr)
                            self.childcommandpipe.send((sock.fileno(), sock.getsockname()[1]))
                        except OSError as err:
                            exc = Exception("cannot connect to {}:{}. errno={}".format(*remoteaddr, errno.errorcode[err.errno]))
                            self.childcommandpipe.send(exc)
                    elif command[0] == 'sa':
                        try:
                            if command[1] == 'prepare':
                                sa = Security.SA(*command[2:])
                                local  = dict(ip=sa.local.ip,  spis=sa.local.spis,  spic=sa.local.spic,  ports=sa.local.ports,  portc=sa.local.portc)
                                self.childcommandpipe.send(local)
                            elif command[1] == 'establish':
                                sa.finalize(**command[2])
                                udps.append(sa.udps)
                                udps.append(sa.udpc)
                                remote = dict(ip=sa.remote.ip, spis=sa.remote.spis, spic=sa.remote.spic, ports=sa.remote.ports, portc=sa.remote.portc)
                                self.childcommandpipe.send(remote)
                            elif command[1] == 'terminate':
                                udps.remove(sa.udps)
                                udps.remove(sa.udpc)
                                sa.terminate()
                                sa = None
                                self.childcommandpipe.send(None)
                        except Exception as exc:
                            self.childcommandpipe.send(exc)
                    else:
                        self.childcommandpipe.send(Exception("unknown command %s", ' '.join(command)))
                    continue

                # Message comming from main process --> send to remote address
                elif obj == self.childmessagepipe:
                    fd,remoteaddr,packet = self.childmessagepipe.recv()
                    sock = clientsockets.get(fd, serversockets.get(fd, mainudp))
                    if sock.fileno() != fd:
                        continue
                    try:
                        if remoteaddr:
                            sock.sendto(packet, remoteaddr)
                        else:
                            sock.sendall(packet)
                    except Exception as e:
                        dispatcherror(*localaddr, *remoteaddr, str(e), packet)

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif obj == maintcp:
                    serversockets.add(*obj.accept())

                # Incomming UDP packet --> decode and send to main process
                elif obj == mainudp:
                    packet,remoteaddr = obj.recvfrom(65536)
                    decodeinfo = Message.SIPMessage.predecode(packet)
                    # Discard inconsistent messages
                    if decodeinfo.status != 'OK':
                        continue
                    
                    self.childmessagepipe.send(('UDP',remoteaddr,obj.getsockname()[1],packet[decodeinfo.istart:decodeinfo.iend]))

                # Incomming TCP buffer --> assemble with previous buffer(done by ServiceSocket class), decode and send to main process
                else:
                    if obj in clientsockets:
                        tcpsockets = clientsockets
                    elif obj in serversockets:
                        tcpsockets = serversockets
                    else:
                        assert(False)
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

                        self.childmessagepipe.send(('TCP',remoteaddr,obj.getsockname()[1],buf[decodeinfo.istart:decodeinfo.iend]))
                        del buf[:decodeinfo.iend]
                            
            clientsockets.cleanup()
            serversockets.cleanup()

class ServiceSockets:
    TIMEOUT = 32.
    
    def __init__(self):
        self.byfd = {}
        self.byaddr = {}

    def add(self, sock, addr):
        newitem = (sock, addr, bytearray(), [time.monotonic()])
        self.byfd[sock.fileno()] = newitem
        self.byaddr[addr] = newitem

    def get(self, fdoraddr, default=None):
        if isinstance(fdoraddr, int):
            return self.byfd.get(fdoraddr, [default])[0]
        return self.byaddr.get(fdoraddr, [default])[0]

    def __iter__(self):
        for value in self.byfd.values():
            yield value[0]

    def __contains__(self, sock):
        return sock.fileno() in self.byfd

    def recvfrom(self, sock):
        sock,addr,buf,lasttime = self.byfd[sock.fileno()]
        lasttime[0] = time.monotonic()
        newbuf = sock.recv(8192)
        if not newbuf:
            self.delete(obj)
        buf += newbuf
        return buf,addr

    def delete(self, fdorsock):
        if isinstance(fdorsock, int):
            fd = fdorsock
        else:
            fd = fdorsock.fileno()
        sock,addr,buf,lasttime = self.byfd[fd]
        try:
            sock.close()
        except:
            pass
        del self.byfd[fd]
        del self.byaddr[addr]

    def cleanup(self):
        # TCP socket that are idle for more than 64*T1 sec are closed [18]
        currenttime = time.monotonic()
        for fd,(sock,addr,buf,lasttime) in list(self.byfd.items()):
            if currenttime - lasttime[0] > self.TIMEOUT:
                self.delete(fd)


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
