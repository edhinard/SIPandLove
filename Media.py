#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import multiprocessing
import multiprocessing.connection
import random
import socket
import struct
import datetime
import ast
import time
import logging
import errno
import collections
import signal
log = logging.getLogger('Media')

from . import Pcap

class Media(threading.Thread):
    defaultcodecs = {
        0 :('PCMU/8000',   None),
        3 :('GSM/8000',    None),
        4 :('G723/8000',   None),
        5 :('DVI4/8000',   None),
        6 :('DVI4/16000',  None),
        7 :('LPC/8000',    None),
        8 :('PCMA/8000',   None),
        9 :('G722/8000',   None),
        10:('L16/44100/2', None),
        11:('L16/44100/1', None),
        12:('QCELP/8000',  None),
        13:('CN/8000',     None),
        14:('MPA/90000',   None),
        15:('G728/8000',   None),
        16:('DVI4/11025',  None),
        17:('DVI4/22050',  None),
        18:('G729/8000',   None)}

    def __init__(self, *, ua, ip=None, port=None, pcap=None, filter=None, loop=False):
        self.ua = ua
        self.stopped = False
        self.localip = ip or ua.transport.localip
        self.localport = None
        self.wantedlocalport = port or 0
        self.remoteip = None
        self.remoteport = None
        self.pcapfilename = pcap
        self.pcapfilter = filter
        self.loop = loop
        self.codecs = [(payloadtype, codecname, codecformat) for payloadtype,(codecname, codecformat) in Media.defaultcodecs.items()]

        self.lock = multiprocessing.Lock()
        self.lock.acquire()
        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = MediaProcess(pipe=childpipe, lock=self.lock)
        self.process.start()

        super().__init__(daemon=True)
        self.start()

    def getlocaloffer(self):
        if self.localport is None:
            self.opensocket(self.localip, self.wantedlocalport)
        sdplines = ['v=0',
                    'o=- {0} {0} IN IP4 0.0.0.0'.format(random.randint(0,0xffffffff)),
                    's=-',
                    'c=IN IP4 {}'.format(self.localip),
                    't=0 0',
                    'm=audio {} RTP/AVP {}'.format(self.localport, ' '.join([str(t) for t,n,f in self.codecs])),
                    'a=sendrecv'
        ]
        sdplines.extend(['a=rtpmap:{} {}'.format(t, n) for t,n,f in self.codecs if n])
        sdplines.extend(['a=fmtp:{} {}'.format(t, f) for t,n,f in self.codecs if f])
        sdplines.append('')
        return ('\r\n'.join(sdplines), 'application/sdp')

    def opensocket(self, localip, localport):
        self.pipe.send(('opensocket', (localip, localport)))
        localportorexc = self.pipe.recv()
        if isinstance(localportorexc, Exception):
            log.error("%s %s", self.process, localportorexc)
            raise localportorexc
        self.localport = localportorexc

    def setremoteoffer(self, sdp):
        for line in sdp.splitlines():
            if line.startswith(b'c='):
                self.remoteip = line.split()[2].decode('ascii')
            if line.startswith(b'm='):
                self.remoteport = int(line.split()[1])
        if self.remoteip is not None and self.remoteport is not None and self.pcapfilename is not None:
            if self.localport is None:
                self.opensocket(self.localip, self.wantedlocalport)
            self.starttransmit()
        return True

    def starttransmit(self):
        self.pipe.send(('starttransmit',((self.remoteip, self.remoteport), (self.pcapfilename, self.pcapfilter), self.loop)))
        ackorexc = self.pipe.recv()
        if isinstance(ackorexc, Exception):
            log.error("%s %s", self.process, ackorexc)
            raise ackorexc

    def stop(self):
        self.stopped = True
        self.pipe.send(('stop', None))
        self.pipe.recv()

    # Thread loop
    def run(self):
        self.lock.acquire()
        if not self.stopped:
            self.ua.bye(self)

class MediaProcess(multiprocessing.Process):
    def __init__(self, pipe, lock):
        super().__init__(daemon=True)
        self.pipe = pipe
        self.lock = lock

    def __str__(self):
        return "pid:{}".format(self.pid)

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        log.info("%s starting process", self)

        running = True
        transmitting = False
        sock = None
        rtpstream = None

        while running:
            # compute sleep time
            #  it depends on state:
            #   -not transmitting -> infinite = wakeup only on incomming data from pipe or socket
            #   -transmitting and wakeup time in the past -> 0 = no sleep = immediate processing
            #   -transmitting and wakeup time in the future -> wakeup time - current time
            currenttime = time.monotonic()
            if not transmitting:
                sleep = None
            else:
                if wakeuptime <= currenttime:
                    sleep = 0
                else:
                    sleep = wakeuptime - currenttime

            # wait for incomming data or timeout
            obj = None
            if sock:
                objs = [sock, self.pipe]
            else:
                objs = [self.pipe]
            for obj in multiprocessing.connection.wait(objs, sleep):
                if obj == sock:
                    # incoming data from socket
                    #  discard data (and log)
                    buf,addr = sock.recvfrom(65536)
                    rtp = RTP.frombytes(buf)
                    log.info("%s %s:%-5d <--- %s:%-5d RTP(%s)", self, *sock.getsockname(), *addr, rtp)
                        
                elif obj == self.pipe:
                    # incomming data from pipe = command from main program. possible commands:
                    #  -opensocket + localaddr:
                    #     create socket, bind it and
                    #     return its local port
                    #  -starttransmit + remoteaddr + pcap + loop:
                    #     start transmitting
                    #     return ack
                    #  -stop:
                    #     stop transmitting and delete current socket if any
                    #     stop process
                    #     return ack
                    command,param = self.pipe.recv()
                    if command == 'opensocket':
                        localaddr = param
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        except Exception as exc:
                            self.pipe.send(exc)
                        else:
                            try:
                                sock.bind(localaddr)
                                localport = sock.getsockname()[1]
                            except OSError as err:
                                sock.close()
                                sock = None
                                exc = Exception("cannot bind UDP socket to {}. errno={}".format(localaddr, errno.errorcode[err.errno]))
                                self.pipe.send(exc)
                            except Exception as exc:
                                sock.close()
                                sock = None
                                self.pipe.send(exc)
                            else:
                                self.pipe.send(localport)
                                log.info("%s start listenning on %s:%d", self, *sock.getsockname())

                    elif command == 'starttransmit':
                        remoteaddr,pcap,loop = param
                        try:
                            rtpstream = RTPStream(*pcap)
                        except Exception as exc:
                            self.pipe.send(exc)
                        else:
                            transmitting = True
                            refrtptime = time.monotonic()
                            wakeuptime = time.monotonic()
                            self.pipe.send('started')
                            log.info("%s start transmitting to %s:%d", self, *remoteaddr)

                    elif command == 'stop':
                        transmitting = False
                        running = False

                    else:
                        self.pipe.send(Exception("Unknown command {}".format(command)))

            if obj is None:
                # multiprocessing.connection.wait timeout
                # time to send next RTP packet if there is one
                wakeuptime,rtp = rtpstream.nextpacket()
                sock.sendto(rtp, remoteaddr)
                log.info("%s %s:%-5d ---> %s:%-5d RTP(%s)", self, *sock.getsockname(), *remoteaddr, RTP.frombytes(rtp))
                if wakeuptime is None:
                    if loop:
                        if not isinstance(loop, bool):
                            loop -= 1
                        rtpstream = RTPStream(*pcap)
                        refrtptime = time.monotonic()
                        wakeuptime = time.monotonic()
                    else:
                        transmitting = False
                        running = False
                        log.info("%s %s:%-5d ---| %s:%-5d EOS", self, *sock.getsockname(), *remoteaddr)
                else:
                    wakeuptime += refrtptime
        # end of while running

        self.pipe.send('stopped')
        log.info("%s stopping process", self)
        self.lock.release()
        if sock:
            sock.close()


class RTP:
    def __init__(self, payload, PT, seq, TS, SSRC, version=2, P=0, X=0, CC=0, M=0):
        self.payload = payload
        self.PT = PT
        self.seq = seq
        self.TS = TS
        self.SSRC = SSRC
        self.version,self.P,self.X,self.CC,self.M = version,P,X,CC,M

    def __str__(self):
        return "PT={} seq=0x{:x} TS=0x{:x} SSRC=0x{:x} + {}bytes".format(self.PT, self.seq, self.TS, self.SSRC, len(self.payload))

    @staticmethod
    def frombytes(buf):
        h0,h1,seq,TS,SSRC = struct.unpack_from('!bbHLL', buf[:12] + 12*b'\x00')
        version = h0>>6
        P = (h0>>5) & 0b1
        X = (h0>>4) & 0b1
        CC = h0 & 0b1111
        M = h1 >> 7
        PT = h1 & 0b01111111
        payload = buf[12:]

        return RTP(payload, PT, seq, TS, SSRC, version, P, X, CC, M)

    def tobytes(self):
        hdr = bytearray(12)
        hdr[0] = self.version<<6 | self.P<<5 | self.X<<4 | self.CC
        hdr[1] = self.M<<7 | self.PT
        struct.pack_into('!HLL', hdr, 2, self.seq, self.TS, self.SSRC)
        return hdr + self.payload


class RTPStream:
    filtercriterions = ('srcport', 'dstport', 'PT', 'SSRC')

    def __init__(self, pcapfilename, pcapfilter=None):
        self.udpstream = Pcap.Pcap(pcapfilename)
        self.pcapfilter = pcapfilter or {}
        extracriterion = set(self.pcapfilter.keys()) - set(RTPStream.filtercriterions)
        if extracriterion:
            raise Exception("Unexpected filter criterion {!}".format(list(extracriterion)))
        self.eof = False
        self.generator = self._generator()
        try:
            dummy,self.nextrtp = next(self.generator)
        except StopIteration:
            self.eof = True

    def nextpacket(self):
        rtp = self.nextrtp
        try:
            wakeuptime,self.nextrtp = next(self.generator)
        except StopIteration:
            self.eof = True
            return None,rtp
        return wakeuptime,rtp

    def _generator(self):
        inittimestamp = None
        for packet in self.udpstream:
            if not packet.udp:
                continue
            rtp = packet.data
            PT,SSRC = struct.unpack_from('!xB6xI', rtp);PT&=0x7f
            params = dict(srcport=packet.udp.srcport, dstport=packet.udp.dstport, PT=PT, SSRC=SSRC)
            for k,v in self.pcapfilter.items():
                if params[k] != v:
                    break
            else:
                if inittimestamp is None:
                    inittimestamp = packet.metadata['timestamp']
                    timestamp = datetime.timedelta()
                if packet.metadata['timestamp'] - inittimestamp < timestamp or packet.metadata['timestamp'] - inittimestamp > timestamp + datetime.timedelta(seconds=5):
                    inittimestamp = packet.metadata['timestamp'] - timestamp - datetime.timedelta(seconds=0.2)
                timestamp = packet.metadata['timestamp'] - inittimestamp
                yield timestamp.total_seconds(),rtp
        self.eof=True
