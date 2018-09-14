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
import ssl
import os
import itertools
log = logging.getLogger('Transport')

from . import Message
from . import Header
from . import Security
from . import Utils


@atexit.register
def cleanup():
    for transport in Transport.instances:
        transport.stop()

class Transport(multiprocessing.Process):
    instances = weakref.WeakSet()
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        Transport.instances.add(instance)
        return instance

    def __init__(self, *, interface=None, address=None, port=None, behindnat=None, protocol='UDP+TCP', maxudp=1300, cafile=None, hostname=None, errorcb=None, sendcb=None, recvcb=None):
        self.started = False

        self.localip = self.localport = None
        self.protocol = protocol.upper()
        if not self.protocol in ('UDP', 'TCP', 'TLS', 'UDP+TCP'):
            log.logandraise(Exception("bad value for protocol transport: {}".format(protocol)))

        # build a list of candidate ip address from parameters 'interface' and 'address'
        addresses = []
        interfaces = Utils.getinterfaces()
        if interface and interface not in interfaces:
            log.logandraise(Exception("unknown interface {}".format(interface)))
        if interface:
            addresses = interfaces[interface]
        else:
            list(map(addresses.extend, interfaces.values()))

        if isinstance(address, int):
            if address < 0:
                log.logandraise(Exception("bad integer value for address ({}). Expecting a positive value".format(address)))
            elif address >= len(addresses):
                log.logandraise(Exception("bad integer value for address ({}). Maximum value is {}".format(address, len(addresses)-1)))
            else:
                addresses = [addresses[address]]
        elif address and address not in addresses:
            log.logandraise(Exception("unknown address {}. Possible values are {}".format(address, addresses)))
            addresses = [address]
        firstaddress = addresses[0]

        # build a list of candidate ports
        if port is not None and (not isinstance(port, int) or port<=0 or port>=65536):
            log.logandraise(Exception("bad value for port ({})".format(port)))
        if port is not None:
            ports = [port]
            firstport = port
        else:
            if self.protocol == 'TLS':
                firstport = 5061
            else:
                firstport = 5060
            ports = range(firstport,65536,2)

        # candidate couples (port, address)
        candidates = itertools.product(ports,addresses)

        # find the first candidate not already used by another transport instance
        reserved = [(t.localport, t.localip) for t in Transport.instances]
        for candidate in candidates:
            if candidate not in reserved:
                break
        else:
            candidate = (firstport, firstaddress)
        self.localport,self.localip = candidate

        if isinstance(behindnat, str):
            if ':' in behindnat:
                nat = behindnat.split(':', 1)
                self.behindnat = (nat[0], int(nat[1]))
            else:
                self.behindnat = (behindnat, None)
        else:
            self.behindnat = behindnat
        self.maxudp = maxudp
        self.cafile = cafile
        self.hostname = hostname
        self.errorcb = errorcb
        self.sendcb = sendcb
        self.recvcb = recvcb
        self.messagepipe,self.childmessagepipe = multiprocessing.Pipe()
        self.commandpipe,self.childcommandpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self)
        self.start()
        self.started = True
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
        except:
            self.stop()
            raise

        self.localsa = self.remotesa = None
        self.establishedSA = False

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    def send(self, message, addr=None):
        issip = isinstance(message, Message.SIPMessage)
        isrequest = isinstance(message, Message.SIPRequest)
        isresponse = isinstance(message, Message.SIPResponse)

        if issip and message.contacturi:
            if self.protocol == 'UDP+TCP':
                message.contacturi.params.pop('transport', None)
            else:
                message.contacturi.params['transport'] = self.protocol

        if (not issip) or isrequest:
            assert addr
            dstip,dstport = addr
            protocol = self.protocol
            if protocol == 'TLS':
                dstport = dstport or 5061
                if issip:
                    message.length = len(message.body)
                fd,srcport = self.gettlssocket(dstip, dstport, cafile=self.cafile, hostname=self.hostname)
                viaport = self.localport
                addr = (dstip, dstport)
            else:
                dstport = dstport or 5060
                if protocol == 'UDP+TCP':
                    if self.maxudp is not None and len(bytes(message)) > self.maxudp:
                        protocol = 'TCP'
                    else:
                        protocol = 'UDP'
                if protocol == 'TCP' and issip:
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

            via = message.header('via') if issip else None
            if via:
                via.protocol = protocol[:3]
                if self.behindnat:
                     via.host,via.port = self.behindnat
                     via.params['rport']=None
                else:
                    via.host = self.localip
                    via.port = viaport if viaport!=5060 else None

        elif isresponse:
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
                fd,srcport = self.gettlssocket(dstip, dstport, message.fd, self.cafile, self.hostname)
                addr = (dstip, dstport)
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

        if issip and self.sendcb:
            self.sendcb(message)

        log.info("%s:%d --%s-> %s:%d (fd=%d)\n%s", self.localip, srcport, protocol, dstip, dstport, fd, message)
        self.messagepipe.send((fd, addr, bytes(message)))

    def recv(self, timeout=None):
        if self.messagepipe.poll(timeout):
            try:
                fd,protocol,(srcip,srcport),dstport,decodeinfo = self.messagepipe.recv()
            except:
                return None
            message = decodeinfo.finish()
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
                if self.recvcb:
                    self.recvcb(message)
                return message
        return None

    def command(self, *args):
        self.commandpipe.send(args)
        ret = self.commandpipe.recv()
        if isinstance(ret, Exception):
            log.logandraise(ret)
        return ret

    def stop(self):
        if self.started:
            self.commandpipe.send(('stop',))
            self.started = False
            self.messagepipe.close()
            self.childmessagepipe.close()
            self.commandpipe.close()
            self.childcommandpipe.close()
            log.info("%s process %d stopped", self, self.pid)

    def openmainUDP(self):
        fd = self.command('main', 'udp')
        return fd

    def openmainTCP(self):
        fd = self.command('main', 'tcp')
        return fd

    def gettcpsocket(self, remoteip, remoteport, fd=None):
        fd,localport = self.command('gettcp', (remoteip, remoteport), fd)
        return fd, localport

    def gettlssocket(self, remoteip, remoteport, fd=None, cafile=None, hostname=None):
        fd,localport = self.command('gettls', (remoteip, remoteport), fd, cafile, hostname)
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
        mainudp = None
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
                        if tcplisteningsocket:
                            tcplisteningsocket.close()
                        if mainudp:
                            mainudp.close()
                        servicesockets.flush()
                        if sa:
                            sa.terminate()
                        self.childcommandpipe.send(None)
                        self.messagepipe.close()
                        self.childmessagepipe.close()
                        self.commandpipe.close()
                        self.childcommandpipe.close()
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
                            except Exception as err:
                                extra = ". errno={}".format(errno.errorcode[err.errno]) if isinstance(err, OSError) else ''
                                exc = Exception("cannot bind TCP socket to {}:{}{}".format(*localaddr, extra))
                                tcplisteningsocket.close()
                                tcplisteningsocket = None
                                self.childcommandpipe.send(exc)
                        elif layer4 == 'udp':
                            try:
                                mainudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                mainudp.bind(localaddr)
                                servicesockets.new(mainudp)
                                self.childcommandpipe.send(mainudp.fileno())
                            except Exception as err:
                                extra = ". errno={}".format(errno.errorcode[err.errno]) if isinstance(err, OSError) else ''
                                exc = Exception("cannot bind UDP socket to {}:{}{}".format(*localaddr, extra))
                                self.childcommandpipe.send(exc)
                    elif command[0] == 'gettcp':
                        remoteaddr,fd = command[1:]
                        for sock in servicesockets:
                            if sock.tcp and (sock.fd==fd or sock.remoteaddr==remoteaddr):
                                break
                        else:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(2)
                                sock.bind((self.localip, 0))
                                sock.connect(remoteaddr)
                                sock = servicesockets.new(sock)
                            except socket.timeout as err:
                                exc = Exception("cannot connect to {}:{}. timeout".format(*remoteaddr))
                                self.childcommandpipe.send(exc)
                                continue
                            except OSError as err:
                                exc = Exception("cannot connect to {}:{}. errno={}".format(*remoteaddr, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                                continue
                        self.childcommandpipe.send((sock.fd, sock.localport))
                    elif command[0] == 'gettls':
                        remoteaddr,fd,cafile,hostname = command[1:]
                        for sock in servicesockets:
                            if sock.tcp and (sock.fd==fd or sock.remoteaddr==remoteaddr):
                                break
                        else:
                            try:
                                sslcontext = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=cafile)
                            except OSError as err:
                                exc = Exception("bad CA file {} {}".format(cafile, err))
                                self.childcommandpipe.send(exc)
                                continue
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(2)
                                sock.bind((self.localip, 0))
                                sock.connect(remoteaddr)
                                sslcontext.check_hostname = bool(hostname)
                                sock = sslcontext.wrap_socket(sock, server_hostname=hostname)
                                sock = servicesockets.new(sock)
                            except socket.timeout as err:
                                exc = Exception("cannot connect to {}:{}. timeout".format(*remoteaddr))
                                self.childcommandpipe.send(exc)
                                continue
                            except ssl.CertificateError as err:
                                exc = Exception("cannot connect to {}:{}. {}".format(*remoteaddr, err))
                                self.childcommandpipe.send(exc)
                                continue
                            except ssl.SSLError as err:
                                exc = Exception("cannot connect to {}:{}. {} {}".format(*remoteaddr, err.library, err.reason))
                                self.childcommandpipe.send(exc)
                                continue
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

                        self.childmessagepipe.send((obj.fd,'UDP',remoteaddr,obj.localport,decodeinfo))

                    elif obj.tcp:
                        protocol = 'TCP'
                        if isinstance(obj.sock, ssl.SSLSocket):
                            protocol = 'TLS'
                        # assemble with previous buffer stored in TCPSocket
                        while True:
                            decodeinfo = Message.SIPMessage.predecode(buf)

                            # Erroneous messages or messages missing a Content-Length make the stream desynchronized
                            if decodeinfo.status == 'ERROR' or (decodeinfo.status == 'OK' and not decodeinfo.framing):
                                obj.close()
                                break

                            # Flush buffer if filled with CRLF
                            if decodeinfo.status == 'EMPTY':
                                if buf:
                                    log.info("%s:%s <-%s-- %s:%d (fd=%d)\n%s", obj.localip, protocol, obj.localport, *remoteaddr, obj.fd, bytes(buf))
                                    del buf[:]
                                break

                            # Ignore inconsistent messages, wait for the rest of the buffer
                            if decodeinfo.status != 'OK':
                                break

                            self.childmessagepipe.send((obj.fd,protocol,remoteaddr,obj.localport,decodeinfo))
                            del buf[:decodeinfo.iend]

                servicesockets.cleanup()


class ServiceSocket:
    def __init__(self, sock, pool):
        self.__dict__.update(dict(
            sock = sock,
            pool = pool,
            fd = sock.fileno(),
            localip = sock.getsockname()[0],
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

    def flush(self):
        for sock in self.copy():
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

    t = snl.Transport(interface='eno1', port=5061, protocol='tcp')
    t.send(snl.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu'),
           ('194.2.137.40',5060)
    )
    t.send(snl.REGISTER('sip:osk.nkims.eu'), '127.0.0.1')
    t.recv(3)
    t.recv(3)
