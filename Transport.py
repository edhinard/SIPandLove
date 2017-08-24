#! /usr/bin/python3
# coding: utf-8

import socket
import select
import sys
import multiprocessing
import time

from . import Message
from . import Header

import socket
import fcntl
import struct


# s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
#  s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
#  while 1:
#    data, addr = s.recvfrom(1508)
#    print "Packet from %r: %r" % (addr,data)


# http://code.activestate.com/recipes/439094
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('ascii'))
    )[20:24])

class Transport(multiprocessing.Process):
    def __init__(self, interface, listenport=5060, proxy=None, tcp_only=False):
        self.listenhost = get_ip_address(interface)
        self.listenport = listenport
        self.proxy = proxy
        self.tcp_only = tcp_only
        self.pipe,self.childpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self, daemon=True)
        self.start()

    def send(self, message, addr=None):
        if not isinstance(message, Message.SIPMessage):
            raise TypeError("expecting SIPMessage subclass as message")

        via = message.getheader('via')
        if isinstance(message, Message.SIPRequest):
            if addr is None and self.proxy:
                addr = self.proxy
            port = 5060

            protocol = 'TCP' if self.tcp_only else 'UDP'
            if via:
                if via.protocol == '???':
                    via.protocol = protocol
                if via.host == '0.0.0.0':
                    via.host = self.listenhost
                if via.port == None and self.listenport != 5060:
                    via.port = self.listenport

        elif isinstance(message, Message.SIPResponse):
            if via:
                protocol = via.protocol
            else:
                protocol = 'TCP' if self.tcp_only else 'UDP'
            if addr is None:
                if via:
                    if protocol == 'TCP':
                        addr = via.host
                    else:
                        addr = via.params.get('received', via.host)
            if addr is None:
                raise Exception("no address where to send response")
            if via:
                if protocol == 'TCP':
                    port = via.port or 5060
                else:
                    port = via.params.get('rport', via.port) or 5060
            else:
                port = 5060

        if protocol == 'TCP' or len(message.body) and not message.getheader('l'):
            message.addheaders(Header.Content_Length(length=len(message.body)))

        self.pipe.send((protocol, (addr, port), message.tobytes()))

    def recv(self, timeout=0.0):
        if self.pipe.poll(timeout):
            protocol,(addr,port),message = self.pipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message:
                if isinstance(message, Message.SIPRequest):
                    via = message.getheader('via')
                    if via:
                        if via.host != addr:
                            via.params['received'] = addr
                        if via.params.has_key('rport'):
                            via.params['received'] = addr
                            via.params['rport'] = port
                return message
        return None
                
    def run(self):
        poll = select.poll()
        poll.register(self.childpipe, select.POLLIN)
        
        maintcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        maintcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        maintcp.bind((self.listenhost, self.listenport))
        maintcp.listen()
        poll.register(maintcp, select.POLLIN)

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((self.listenhost, self.listenport))
        poll.register(udp, select.POLLIN)

        tcpsockets = ServiceSockets(poll)
        while True:
            for fd,event in poll.poll(1000):
                # Packet comming from upper layer --> send to remote address
                if fd == self.childpipe.fileno():
                    protocol,remoteaddr,packet = self.childpipe.recv()
                    if protocol == 'TCP':
                        tcpsockets.sendto(packet, remoteaddr)
                    elif protocol == 'UDP':
                        udp.sendto(packet, remoteaddr)

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif fd == maintcp.fileno():
                    tcpsockets.addnew(*maintcp.accept())

                # Incomming UDP packet --> decode and send to upper layer
                elif fd == udp.fileno():
                    packet,remoteaddr = udp.recvfrom(8192)
                    decodeinfo = Message.SIPMessage.predecode(packet)

                    # Discard inconsistent messages
                    if not decodeinfo.klass or not decodeinfo.ibody:
                        continue
                        
                    # If the message has no Content-Length the message body is assumed to end at the end of the packet [18.3]
                    if decodeinfo.contentlength is None:
                        decodeinfo.iend = len(packet)
                        decodeinfo.contentlength = decodeinfo.iend - decodeinfo.ibody

                    # Truncated Request --> 400, truncated Response are discarded [18.3]
                    if decodeinfo.contentlength > decodeinfo.iend - decodeinfo.ibody:
                        if decodeinfo.klass == Message.SIPRequest:
                            message = decodeinfo.finish()
                            udp.sendto(message.response(400).tobytes(), remoteaddr)
                        elif decodeinfo.klass == Message.SIPResponse:
                            continue

                    self.childpipe.send(('UDP',remoteaddr,packet[decodeinfo.istart:decodeinfo.iend]))

                # Incomming TCP buffer --> assemble with previous buffer, decode and send to upper layer
                else:
                    newbuf = tcpsockets.readfrom(fd)
                    # Socket closed by peer
                    if not newbuf:
                        tcpsockets.delete(fd)
                        continue
                    
                    buf,remoteaddr = tcpsockets.getinfo(fd)
                    buf += newbuf
                    while True:
                        decodeinfo = Message.SIPMessage.predecode(buf)

                        # Ignore inconsistent messages, wait for the rest of the buffer
                        if not decodeinfo.klass or not decodeinfo.ibody:
                            break

                        # If the message miss a Content-Length, the stream cannot be synchronized
                        #   --> 400 for Requests and socket is closed
                        if decodeinfo.contentlength is None:
                            decodeinfo.iend = decodeinfo.ibody
                            decodeinfo.contentlength = 0
                            if decodeinfo.klass == Message.SIPRequest:
                                message = decodeinfo.finish()
                                tcpsockets.sendto(message.response(400).tobytes(), remoteaddr)
                            tcpsockets.delete(fd)
                            break

                        self.childpipe.send(('TCP',remoteaddr,buf[decodeinfo.istart:decodeinfo.iend]))
                        del buf[:decodeinfo.iend]
            decodeinfo = None
                            
            tcpsockets.cleanup()

class ServiceSockets:
    TIMEOUT = 32.
    
    def __init__(self, poll):
        self.poll = poll
        self.byfd = {}
        self.byaddr = {}

    def addnew(self, sock, addr):
        newitem = (sock, addr, bytearray(), [time.monotonic()])
        fd = sock.fileno()
        self.byfd[fd] = newitem
        self.byaddr[addr] = newitem
        self.poll.register(fd, select.POLLIN | select.POLLHUP)

    def sendto(self, packet, addr):
        if addr not in self.byaddr:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(addr)
                self.addnew(sock, addr)
            except:
                return
        sock,addr,buf,lasttime = self.byaddr[addr]
        lasttime[0] = time.monotonic()
        sock.send(packet)

    def readfrom(self, fd):
        sock,addr,buf,lasttime = self.byfd[fd]
        lasttime[0] = time.monotonic()
        return sock.recv(8192)

    def getinfo(self, fd):
        sock,addr,buf,lasttime = self.byfd[fd]
        return buf,addr

    def delete(self, fd):
        self.poll.unregister(fd)
        item = self.byfd[fd]
        addr = item[1]
        del self.byfd[fd]
        del self.byaddr[addr]

    def cleanup(self):
        # TCP socket that are idle for more than 64*T1 sec are closed [18]
        currenttime = time.monotonic()
        for fd,(sock,addr,buf,lasttime) in list(self.byfd.items()):
            if currenttime - lasttime[0] > self.TIMEOUT:
                self.delete(fd)

if __name__ == '__main__':                
    t = Transport('eno1', proxy='194.12.137.40', listenport=5061, tcp_only=True)
    t.send(Message.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu'))
    t.send(Message.REGISTER('sip:osk.nkims.eu'))
    print(t.recv(5))
    print(t.recv(5))
