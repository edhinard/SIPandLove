#! /usr/bin/env python3
# coding:utf-8

import sys
import threading
import multiprocessing
import time
import signal
import random
import string
import errno
import logging
import socket
import re

log = logging.getLogger('MSRP')

class MSRP:
    def __init__(self, *, ua, ip=None, port=None, connect=True):
        self.ua = ua
        self.localip = ip or ua.transport.localip
        self.localport = port or 0
        self.doconnect = connect
        self.remoteip = None
        self.remoteport = None
        self.originaloffer = None
        self.session = 'SNL_' + ''.join((random.choice(string.ascii_letters + string.digits) for _ in range(14)))

        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = MSRPProcess(pipe=childpipe)
        self.process.start()

    def __str__(self):
        return "pid:{}".format(self.process.pid)

    def getlocaloffer(self):
        if self.originaloffer is None:
            self.originaloffer = True
            if self.doconnect:
                self.opensocket()
        elif self.originaloffer == False:
            if self.doconnect:
                self.opensocket(listening=True)
        sdplines = ['v=0',
                    'o=- {0} {0} IN IP4 0.0.0.0'.format(random.randint(0,0xffffffff)),
                    's=-',
                    'c=IN IP4 {}'.format(self.localip),
                    't=0 0',
                    'm=message {} TCP/MSRP *'.format(self.localport),
                    'a=accept-types:text/plain',
                    'a=path:msrp://{}:{}/{};tcp'.format(self.localip, self.localport, self.session),
                    ''
        ]
        log.info("{0} local path msrp://{0.localip}:{0.localport}/{0.session}".format(self))
        return ('\r\n'.join(sdplines), 'application/sdp')

    MSRP_RE = re.compile(r'a=path:msrp://(?P<ip>[^:]+):(?P<port>\d+)/(?P<session>[^;]+)')
    def setremoteoffer(self, sdp):
        for line in sdp.splitlines():
#            if line.startswith(b'c='):
#                self.remoteip = line.split()[2].decode('ascii')
#            if line.startswith(b'm='):
#                self.remoteport = int(line.split()[1])
#        log.info("{0} remote path {0.remoteip}:{0.remoteport}".format(self))
            try:
                line = line.decode('ascii')
            except:
                continue
            m = self.MSRP_RE.match(line)
            if m:
                self.remoteip = m.group('ip')
                self.remoteport = int(m.group('port'))
                self.remotesession = m.group('session')
                log.info("{0} remote path msrp://{0.remoteip}:{0.remoteport}/{0.remotesession}".format(self))
        if self.originaloffer is None:
            self.originaloffer = False
        elif self.originaloffer == True:
            if self.doconnect:
                self.connect()
                self.send(
b'''MSRP dkei38sd SEND\r
Message-ID: 4564dpWd\r
Byte-Range: 1-*/8\r
Content-Type: text/plain\r
\r
abcd\r
-------dkei38sd+\r
\r
MSRP dkei38ia SEND\r
Message-ID: 4564dpWd\r
Byte-Range: 5-8/8\r
Content-Type: text/plain\r
\r
EFGH\r
-------dkei38ia$\r
''')
        return True

    def command(self, *args):
        self.pipe.send(args)
        ret = self.pipe.recv()
        if isinstance(ret, Exception):
            log.logandraise(ret)
        return ret

    def opensocket(self, listening=False):
        self.localport = self.command('opensocket', ((self.localip, self.localport), listening))

    def connect(self):
        self.command('connect', (self.remoteip, self.remoteport))

    def send(self, buf):
        self.command('send', buf)

    def stop(self):
        self.command('stop', None)


class MSRPProcess(multiprocessing.Process):
    def __init__(self, pipe):
        super().__init__(daemon=True)
        self.pipe = pipe

    def __str__(self):
        return "pid:{}".format(self.pid)

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        log.info("%s starting process", self)

        running = True
        listeningsock = None
        remoteaddr = None
        sock = None

        while running:
            # wait for incomming data
            obj = None
            objs = [self.pipe]
            if remoteaddr:
                objs.append(sock)
            if listeningsock:
                objs.append(listeningsock)
            for obj in multiprocessing.connection.wait(objs):
                if obj == listeningsock:
                    # incomming TCP connection
                    if sock:
                        sock.close()
                    sock,remoteaddr = listeningsock.accept()
                    log.info("%s connected to %s:%d", self, *remoteaddr)

                elif obj == sock:
                    # incoming data from socket
                    buf = sock.recv(65536)
                    if not buf:
                        sock.close()
                        sock = None
                        remoteaddr = None
                    else:
                        log.info("%s %s:%-5d <--- %s:%-5d MSRP\n%s", self, *sock.getsockname(), *remoteaddr, buf)
                        
                elif obj == self.pipe:
                    # incomming data from pipe = command from main program. possible commands:
                    #  -opensocket + localaddr + listening:
                    #     create socket
                    #     bind it
                    #     (optional: listen to it)
                    #     return its local port
                    #  -connect + remoteaddr:
                    #     connect socket
                    #     return ack
                    #  -send + buffer:
                    #     send
                    #     return ack
                    #  -stop:
                    #     close socket if any
                    #     stop process
                    #     return ack
                    command,param = self.pipe.recv()
                    if command == 'opensocket':
                        localaddr,listening = param
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        except Exception as exc:
                            self.pipe.send(exc)
                            continue
                        try:
                            s.bind(localaddr)
                            localport = s.getsockname()[1]
                        except OSError as err:
                            s.close()
                            exc = Exception("cannot bind TCP socket to {}. errno={}".format(localaddr, errno.errorcode[err.errno]))
                            self.pipe.send(exc)
                            continue
                        except Exception as exc:
                            s.close()
                            self.pipe.send(exc)
                            continue
                        if listening:
                            try:
                                s.listen()
                            except Exception as exc:
                                s.close()
                                self.pipe.send(exc)
                                continue
                            listeningsock = s
                            log.info("%s listening on %s:%d", self, *s.getsockname())
                        else:
                            sock = s
                            log.info("%s socket opened on %s:%d", self, *s.getsockname())
                        self.pipe.send(localport)

                    elif command == 'connect':
                        remoteaddr = param
                        try:
                            sock.connect(remoteaddr)
                        except socket.timeout as err:
                            sock.close()
                            sock = None
                            exc = Exception("cannot connect to {}:{}. timeout".format(*remoteaddr))
                            remoteaddr = None
                            self.pipe.send(exc)
                        except OSError as err:
                            sock.close()
                            sock = None
                            exc = Exception("cannot connect to {}:{}. errno={}".format(*remoteaddr, errno.errorcode[err.errno]))
                            remoteaddr = None
                            self.pipe.send(exc)
                        else:
                            self.pipe.send('connected')
                            log.info("%s connected to %s:%d", self, *remoteaddr)

                    elif command == 'send':
                        buf = param
                        sock.sendall(buf)
                        log.info("%s %s:%-5d ---> %s:%-5d MSRP\n%s", self, *sock.getsockname(), *remoteaddr, buf)
                        self.pipe.send('sent')

                    elif command == 'stop':
                        running = False

                    else:
                        self.pipe.send(Exception("Unknown command {}".format(command)))
        # end of while running

        self.pipe.send('stopped')
        log.info("%s stopping process", self)
        if sock:
            sock.close()
        if listeningsock:
            listeningsock.close()
