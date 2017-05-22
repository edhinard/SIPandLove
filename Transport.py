#! /usr/bin/python3
# coding: utf-8

import socket
import select
import sys
import multiprocessing
import threading
import time

import Message

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
        struct.pack('256s', ifname[:15])
    )[20:24])

#
# transport doit connaitre son ip (donner l'if est ok)
# envoyer une requete est différent d'envoyer une réponse
#
#  req: il faut donner au transport la destination ip/port/protocol
#    transport complète Via avec localip et localport
#    possible changement de protocole TCP->UDP si trop gros
#
#  resp: transport trouve ip/port dans le via
#
#  dans les 2 cas:
#    ajout content-length
#    retour possible d'erreur vers la transaction : erreur tcp ou icmp
#
#donc:
# dans le pipe on place bien dans les 2 sens :
#  protocol, remoteaddr, packet(bytes)
#   + erreur=string dans le sens transport -> transaction
#
# en émission, ajout du CL, récup remoteaddr du via ou ajout localaddr dans le via, conversion tobytes
# en réception, conversion frombytes, ajout via.received si requete et transfert au transaction manager

class Transport(threading.Thread):
    def __init__(self, interface=None, listenport=5060, tcp_only=False):
        threading.Thread.__init__(self, daemon=True)
        if interface is None:
            self.listenhost = '0.0.0.0'
        else:
            self.listenhost = get_ip_address(interface)
        self.listenport = listenport
        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = multiprocessing.Process(target=Transport.processloop, args=(self.listenhost, self.listenport, childpipe, tcp_only), daemon=True)
        self.process.start()
        self.ingress = None
        self.start()

    def send(self, message, addr=None, protocol=None):
        if not issubclass(message, Message.SIPMessage):
            raise TypeError('expecting SIPMessage subclass as message')
        try:
            via = message.getheader('via')
        except:
            via = None
        if isinstace(message, Message.SIPrequest):
            request = message
            if via is None:
                via = request.addheaders('Via: SIP/2.0/UDP 0.0.0.0')[0]
            via.host = self.listenhost
            if self.localport
            

        elif isinstance(message, Message.SIPResponse):
            response = message
            if not response.hasheader('via'):
                raise Exception(
        self.pipe.send((protocol, addr, message.tobytes()))

    # Thread loop
    def run(self):
        while True:
            protocol,addr,message = self.pipe.recv()
            message = Message.SIPMessage.frombytes(message)
            if message and self.ingress:
                message.transport = self
                # modify Via: with protocol and addr ?
                self.ingress(message)
                
    # Process loop
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

                # Packet comming from upper layer --> send to remote address
                if fd == pipe.fileno():
                    transport,remoteaddr,packet = pipe.recv()
                    if transport == 'tcp':
                        tcpsockets.sendto(packet, remoteaddr)
                    elif transport == 'udp':
                        udp.sendto(packet, remoteaddr)

                # Incomming TCP connection --> new socket added (will be read in the next result of poll)
                elif fd == maintcp.fileno():
                    tcpsockets.addnew(*maintcp.accept())

                # Incomming UDP packet --> decode and send to upper layer
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

                        pipe.send(('tcp',remoteaddr,buf[decodeinfo.istart:decodeinfo.iend]))
                        del buf[:decodeinfo.iend]
            decodeinfo = None
                            
            tcpsockets.cleanup()

DEFAULT = Transport('eno1')
            
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

if __name__ == '__main__':                
    t = Transport('x')
    while 1:
        transport,dstaddr,message = t.pipe.recv()
        message = Message.SIPMessage.frombytes(message)
        print(message)
        if isinstance(message, Message.SIPRequest):
            t.pipe.send((transport,dstaddr,message.response(200).tobytes()))
        else:
            t.pipe.send((transport,dstaddr,b'OK'))
