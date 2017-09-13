#! /usr/bin/python3
# coding: utf-8

import sys
import multiprocessing
import random
import socket
import time
import logging
log = logging.getLogger('Media')

class Media(multiprocessing.Process):
    def __init__(self, localip, rtpfile, codecs, owner=None):
        self.localip = localip
        self.localport = None
        self.remoteip = None
        self.remoteport = None
        if isinstance(rtpfile, str):
            self.rtpfile = open(rtpfile, 'rb')
        else:
            self.rtpfile = rtpfile
        self.codecs = codecs or [(0,'PCMU/8000',None),
                                 (8,'PCMA/8000',None)]
        self.owner = owner or '0.0.0.0'
        self.pipe,self.childpipe = multiprocessing.Pipe()
        multiprocessing.Process.__init__(self, daemon=True)
        self.start()
        ret = self.pipe.recv()
        if not isinstance(ret, int):
            log.error(ret)
            raise ret
        self.localport = ret
        log.debug("%s starting process %d", self, self.pid)

    def __str__(self):
        return "{}:{}".format(self.localip, self.localport)

    @property
    def localoffer(self):
        sdplines = ['v=0',
                    'o=- {0} {0} IN IP4 {1}'.format(random.randint(0,0xffffffff), self.owner),
                    's=-',
                    'm=audio {} RTP/AVP {}'.format(self.localport, ' '.join([str(t) for t,n,f in self.codecs])),
                    'c=IN IP4 {}'.format(self.localip)]
        sdplines.extend(['a=rtpmap:{} {}'.format(t, n) for t,n,f in self.codecs if n])
        sdplines.extend(['a=fmtp:{} {}'.format(t, f) for t,n,f in self.codecs if f])
        return '\r\n'.join(sdplines)

    def setparticipantoffer(self, sdp):
        for line in sdp.splitlines():
            if line.startswith(b'c='):
                self.remoteip = line.split()[2]
            if line.startswith(b'm='):
                self.remoteport = int(line.split()[1])

    def transmit(self):
        if self.remoteip is None or self.remoteport is None:
            raise Exception("missing participant offer")
        self.pipe.send((self.remoteip, self.remoteport))
    
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.localip, 0))
        except Exception as e:
            self.childpipe.send(e)
            return
        self.childpipe.send(sock.getsockname()[1])
        
        remoteaddr = self.childpipe.recv()
        while True:
            sock.sendto(self.rtpfile.read(64), remoteaddr)
            time.sleep(0.5)
