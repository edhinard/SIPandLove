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
    addr = addr or (None,5060)
    if isinstance(addr, str):
        if ':' in addr:
            ip,port = addr.split(':', 1)
        else:
            ip = addr
            port = 5060
    elif isinstance(addr, (list,tuple)):
        if len(addr) != 2:
            raise Exception("expecting 2 values in addr ({!r})".format(addr))
        ip,port = addr
    else:
        raise Exception("addr should be a 2uple or a string not {!r}".format(addr))
    try:
        port = int(port)
    except:
        raise Exception("port number in addr ({!r}) should be an int".format(port))
    return ip,port

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
            try:
                self.localip = get_ip_address(localiporinterface)
            except Exception as e:
                log.error("%s %r", e, localiporinterface)
                raise
        else:
            self.localip = localiporinterface
        self.localport = localport or 5060
        self.localsa = self.remotesa = None
        self.establishedSA = False
        self.tcp_only = tcp_only
        self.errorcb = None
        self.messagepipe,self.childmessagepipe = multiprocessing.Pipe()
        self.commandpipe,self.childcommandpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self)
        self.start()
        log.info("%s starting process %d", self, self.pid)
        try:
            ip,port = self.command('open', 'tcp', self.localip, self.localport)
            log.info("TCP listening on %s:%d", ip, port)
            ip,port = self.command('open', 'udp', self.localip, self.localport)
            log.info("UDP listening on %s:%d", ip, port)
        except Exception as e:
            log.error("%s - %s", self, e)
            raise Exception("Transport initialization error") from None

    def stop(self):
        self.commandpipe.send(('stop',))

    def command(self, *args):
        self.commandpipe.send(args)
        ret = self.commandpipe.recv()
        if isinstance(ret, Exception):
            raise ret
        return ret

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    def send(self, message, addr=None, protocol=None):
        if not isinstance(message, Message.SIPMessage):
            err = "expecting a SIPMessage not {}".format(type(message))
            log.error("%s %s", self, err)
            raise TypeError(err)
        try:
            dstip, dstport = splitaddr(addr)
        except Exception as err:
            log.error("%s %s", self, err)
            raise

        srcport = self.localport
        if self.localsa and self.remotesa and dstip == self.remotesa['ip']:
            if dstport == self.remotesa['ports']:
                srcport = self.localsa['portc']
            elif dstport == self.remotesa['portc']:
                srcport = self.localsa['ports']

        via = message.header('via')
        if isinstance(message, Message.SIPRequest):
            if dstip is None:
                raise Exception("missing address")

            protocol = 'TCP' if self.tcp_only else 'UDP'
            if via:
                via.protocol = protocol
                via.host = self.localip
                port = self.localsa['ports'] if self.establishedSA else self.localport
                if port != 5060:
                    via.port = port
                else:
                    via.port = None

        elif isinstance(message, Message.SIPResponse):
            if via:
                protocol = via.protocol
            else:
                protocol = 'TCP' if self.tcp_only else 'UDP'
            if dstip is None:
                if via:
                    if protocol == 'TCP':
                        dstip = via.host
                    else:
                        dstip = via.params.get('received', via.host)
            if dstip is None:
                raise Exception("no address where to send response")
            if via:
                if protocol == 'TCP':
                    port = via.port or 5060
                else:
                    port = via.params.get('rport', via.port) or 5060

        if (protocol == 'TCP' or len(message.body)) and not message.header('l'):
            message.addheaders(Header.Content_Length(length=len(message.body)))

        esp = ''
        if self.establishedSA and dstip == self.remotesa['ip']:
            esp = '/ESP'
        log.info("%s:%d --%s%s-> %s:%d\n%s", self.localip, srcport, protocol, esp, dstip, dstport, message)
        self.messagepipe.send((protocol, srcport, (dstip, dstport), message.tobytes()))

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
                if self.establishedSA and srcip == self.remotesa['ip'] and dstport in (self.localsa['portc'],self.localsa['ports']):
                    esp = '/ESP'
                log.info("%s:%s <-%s%s-- %s:%d\n%s", self.localip, dstport, protocol, esp, srcip, srcport, message)
                return message
        return None

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
        sa = None
        tcplisten = []
        udps = []
        tcpsockets = ServiceSockets()
        while True:
            sockets = [self.childcommandpipe, self.childmessagepipe] + tcplisten + udps + list(tcpsockets)
            for obj in multiprocessing.connection.wait(sockets, 1):
                # Command comming from upper layer
                if obj == self.childcommandpipe:
                    command = self.childcommandpipe.recv()
                    if command[0] == 'stop':
                        if sa:
                            sa.terminate()
                        self.childcommandpipe.send(None)
                        return
                    if command[0] == 'open':
                        protocol, localip, localport = command[1:]
                        if protocol == 'tcp':
                            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            try:
                                tcp.bind((localip, localport))
                                tcp.listen()
                            except OSError as err:
                                exc = Exception("cannot bind TCP socket to {}:{}. errno={}".format(localip, localport, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                            else:
                                tcplisten.append(tcp)
                                self.childcommandpipe.send(tcp.getsockname())
                        elif protocol == 'udp':
                            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            try:
                                udp.bind((localip, localport))
                            except OSError as err:
                                exc = Exception("cannot bind UDP socket to {}:{}. errno={}".format(localip, localport, errno.errorcode[err.errno]))
                                self.childcommandpipe.send(exc)
                            else:
                                udps.append(udp)
                                self.childcommandpipe.send(udp.getsockname())
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

                # Message comming from upper layer --> send to remote address
                if obj == self.childmessagepipe:
                    protocol,srcport,dstaddr,packet = self.childmessagepipe.recv()
                    try:
                        sock = None
                        if protocol == 'TCP':
                            if sa and sa.state == 'created' and srcport==sa.local.portc:
                                sock = sa.tcpc
                            elif sa and sa.state == 'created' and srcport==sa.local.ports:
                                sock = sa.tcps
                            elif srcport==localport:
                                sock = tcpsockets
                        elif protocol == 'UDP':
                            if sa and sa.state == 'created' and srcport==sa.local.portc:
                                sock = sa.udpc
                            elif sa and sa.state == 'created' and srcport==sa.local.ports:
                                sock = sa.udps
                            elif srcport==localport:
                                sock = udps[0]
                        if sock:
                            sock.sendto(packet, dstaddr)
                        err = None
                    except Exception as e:
                        dispatcherror(self.localip, self.localport, *dstaddr, str(e), packet)
                        continue

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif obj in tcplisten:
                    tcpsockets.add(*obj.accept())

                # Incomming UDP packet --> decode and send to upper layer
                elif obj in udps:
                    packet,remoteaddr = obj.recvfrom(65536)
                    decodeinfo = Message.SIPMessage.predecode(packet)
                    # Discard inconsistent messages
                    if decodeinfo.status != 'OK':
                        continue
                    
                    self.childmessagepipe.send(('UDP',remoteaddr,obj.getsockname()[1],packet[decodeinfo.istart:decodeinfo.iend]))

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

                        self.childmessagepipe.send(('TCP',remoteaddr,buf[decodeinfo.istart:decodeinfo.iend]))
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
