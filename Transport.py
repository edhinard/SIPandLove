#! /usr/bin/python3
# coding: utf-8

import socket
import select
import sys
import multiprocessing
import time

import Message

class Transport:
    def __init__(self, interface, listenport=5060, tcp_only=False):
        self.listenhost = '172.20.35.253' # interface -> ip address
        self.listenhost = '192.168.1.18'
        self.listenport = listenport
        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = multiprocessing.Process(target=Transport.processloop, args=(self.listenhost, self.listenport, childpipe, tcp_only))
        self.process.start()

    def send(self, message, addr, protocol):
        if not issubclass(message, Message.SIPMessage):
            raise TypeError('expecting SIPMessage subclass as message')
        self.pipe.send((protocol, addr, message.tobytes()))

    def recv(self):
        while True:
            protocol,addr,message = self.pipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message:
                return (protocol, addr, message)
        
    @staticmethod
    def processloop(srcip, srcport, pipe, tcp_only):
        poll = select.poll()
        poll.register(pipe, select.POLLIN)
        
        maintcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        maintcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        maintcp.bind((srcip, srcport))
        maintcp.listen()
        poll.register(maintcp, select.POLLIN)

        if not tcp_only:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((srcip, srcport))
            poll.register(udp, select.POLLIN)

        tcpsockets = ServiceSockets(poll)
        while True:
            for fd,event in poll.poll(1000):

                # Packet comming from Transaction layer --> send to remote address
                if fd == pipe.fileno():
                    transport,remoteaddr,packet = pipe.recv()
                    if transport == 'tcp':
                        tcpsockets.sendto(packet, remoteaddr)
                    elif transport == 'udp':
                        udp.sendto(packet, remoteaddr)

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif fd == maintcp.fileno():
                    tcpsockets.addnew(*maintcp.accept())

                # Incomming UDP packet --> decode and send to Transaction layer
                elif not tcp_only and fd == udp.fileno():
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

                    pipe.send(('udp',remoteaddr,packet[decodeinfo.istart:decodeinfo.iend]))

                # Incomming TCP buffer --> assemble with previous buffer, decode and send to Transaction layer
                else:
                    newbuf = tcpsockets.readfrom(fd)
                    # Socker closed by peer
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

                        pipe.send(('tcp',remoteaddr,buf[decodeinfo.istart:decodeinfo.iend]))
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
        print(len(self.byfd))
        for fd,(sock,addr,buf,lasttime) in list(self.byfd.items()):
            if currenttime - lasttime[0] > self.TIMEOUT:
                self.delete(fd)

t = Transport('x')
while 1:
    transport,dstaddr,message = t.pipe.recv()
    message = Message.SIPMessage.frombytes(message)
    print(message)
    if isinstance(message, Message.SIPRequest):
        t.pipe.send((transport,dstaddr,message.response(200).tobytes()))
    else:
        t.pipe.send((transport,dstaddr,b'OK'))

            
