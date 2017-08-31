#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import time
import logging

from . import Message

log = logging.getLogger('Transaction')

def clientidentifier(request):
    return (request.branch, request.getheader('CSeq').method)
def serveridentifier(request):
    via = request.getheader('Via')
    if via.port:
        sentby = "{}:{}".format(via.host, via.port)
    else:
        sentby = via.host
    return (request.branch, sentby, request.getheader('CSeq').method)

class Transaction:
    def __init__(self, request, transport, addr, timermanager, T1, T2, T4):
        self.id = self.identifier(request)
        self.request = request
        log.info("%s <-- New transaction", self)
        self.transport = transport
        self.addr = addr
        self.timermanager = timermanager
        self.T1 = T1
        self.T2 = T2
        self.T4 = T4
        self.lock = threading.Lock()
        self.events = []
        self._terminated = threading.Event()
        with self.lock:
            self.init()
        log.info("%s initial state %s", self, self.state)

    def __str__(self):
        return "/".join(self.id)

    def _getterminated(self):
        return self._terminated.is_set()
    def _setterminated(self, v):
        if v:
            self._terminated.set()
        else:
            self._terminated.clear()
    terminated = property(_getterminated, _setterminated)
    
    def wait(self):
        self._terminated.wait()
        #return self.events[-1]

    def armtimer(self, name, duration):
        self.timermanager.arm(duration, self.timer, name, self.state)

    def response(self, response):
        with self.lock:
            eventcb = getattr(self, '{}_{}xx'.format(self.state, response.familycode), None)
            if eventcb:
                state = self.state
                log.info("%s <-- Response %s %s", self, response.code, response.reason)
                eventcb()
                if self.state == state:
                    log.info("%s keeping state %s", self, self.state)
                else:
                    log.info("%s changing to state %s", self, self.state)

    def request(self, request):
        with self.lock:
            eventcb = getattr(self, '{}_Request'.format(self.state), None)
            if eventcb:
                eventcb()

    def timer(self, name, state):
        eventcb = None
        with self.lock:
            if state == self.state:
                eventcb = getattr(self, '{}_Timer{}'.format(self.state, name), None)
                if eventcb:
                    log.info("%s <-- Timer %s", self, name)
                    eventcb()
                    if self.state == state:
                        log.info("%s keeping state %s", self, self.state)
                    else:
                        log.info("%s changing to state %s", self, self.state)
                
def ClientTransaction(request, *args, **kwargs):
    if isinstance(request, Message.INVITE):
        return INVITEclientTransaction(request, *args, **kwargs)
    else:
        return NonINVITEclientTransaction(request, *args, **kwargs)          
def ServerTransaction(request, *args, **kwargs):
    if isinstance(request, Message.INVITE):
        return INVITEserverTransaction(request, *args, **kwargs)
    else:
        return NonINVITEserverTransaction(request, *args, **kwargs)

class NonINVITEclientTransaction(Transaction):
    identifier = staticmethod(clientidentifier)

    def init(self):
        self.transport.send(self.request, self.addr)
        self.state = 'Trying'
        self.Eduration = self.T1
        self.armtimer('E', self.Eduration)
        self.armtimer('F', 64*self.T1)

    def Trying_TimerE(self):
        self.transport.send(self.request, self.addr)
        self.Eduration = min(2*self.Eduration, self.T2)
        self.armtimer('E', self.Eduration)
        
    def Trying_TimerF(self):
        self.state = 'Terminated'
        self.terminated = True

    def Trying_1xx(self):
        # resp to TU
        self.state = 'Proceeding'
        self.armtimer('E', self.T1)
        self.armtimer('F', 64*self.T1)

    def Trying_23456(self):
        # resp to TU
        self.state = 'Completed'
        self.armtimer('K', self.T4)
    Trying_2xx = Trying_3xx = Trying_4xx = Trying_5xx = Trying_6xx = Trying_23456

    def Completed_TimerK(self):
        self.state = 'Terminated'
        self.terminated = True

class INVITEclientTransaction(Transaction):
    identifier = staticmethod(clientidentifier)

    def init(self):
        self.transport.send(self.request, self.addr)
        self.state = 'Calling'
        self.Aduration = self.T1
        self.armtimer('A', self.Aduration)
        self.armtimer('B', 64*self.T1)

    def Calling_TimerA(self):
        self.transport.send(self.request, self.addr)
        self.Aduration *= 2
        self.armtimer('A', self.Aduration)
        
    def Calling_TimerB(self):
        self.state = 'Terminated'
        self.terminated = True

    def Calling_1xx(self):
        self.state = 'Proceeding'

    def Calling_2xx(self):
        self.state = 'Terminated'
        self.terminated = True
        
    def Calling_3456(self):
        self.transport.send(ack, self.addr)
        self.state = 'Completed'
        self.armtimer('D', 32)
    Calling_3xx = Calling_4xx = Calling_5xx = Calling_6xx = Calling_3456
        
    def Proceeding_1xx(self):
        pass
        
    def Proceeding_2xx(self):
        self.state = 'Terminated'
        self.terminated = True
        
    def Proceeding_3456(self):
        self.transport.send(ack)
        self.armtimer('D', 32)
        self.state = 'Completed'
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Completed_3456(self):
        self.transport.send(ack, self.addr)
    Completed_3xx = Completed_4xx = Completed_5xx = Completed_6xx = Completed_3456

    def Completed_TimerD(self):
        self.state = 'Terminated'
        self.terminated = True



if __name__ == '__main__':
    from . import Transport
    from . import Timer

    import logging.config
    LOGGING = {
        'version': 1,
        'formatters': {
            'simple': {
                'format': "%(asctime)s %(name)s %(levelname)s %(message)s"
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'simple',
                'level': 'INFO'
            }
        },
        'loggers': {
            'Transaction': {
                'level': 'INFO'
            },
            'Transport': {
                'level': 'INFO'
            }
        },
        'root': {
            'handlers': ['console']
        }
    }
    logging.config.dictConfig(LOGGING)
    transport = Transport.Transport(Transport.get_ip_address('eno1'), listenport=5061)
    timermanager = Timer.TimerManager()

    request = Message.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    transaction = ClientTransaction(request, transport, '194.2.137.40', timermanager, T1=.5, T2=4., T4=5.)
    while not transaction.terminated:
        message = transport.recv(3)
        if isinstance(message, Message.SIPResponse):
            id = clientidentifier(message)
            assert(id == transaction.id)
            transaction.response(message)


    request = Message.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    transaction = ClientTransaction(request, transport, '127.0.0.1', timermanager, T1=.5, T2=4., T4=5.)
    while not transaction.terminated:
        message = transport.recv(3)
        if isinstance(message, Message.SIPResponse):
            id = clientidentifier(message)
            assert(id == transaction.id)
            transaction.response(message)
            
