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
        self.transport = transport
        self.addr = addr
        self.timermanager = timermanager
        self.T1 = T1
        self.T2 = T2
        self.T4 = T4
        self.lock = threading.Lock()
        self.events = []
        self._final = threading.Event()
        self._terminated = threading.Event()
        with self.lock:
            self.init()
        log.info("%s <-- New transaction", self)

    def __str__(self):
        return "{}-{}".format("/".join(self.id), self.state)

    def _getfinal(self):
        return self._final.is_set()
    def _setfinal(self, v):
        if v:
            self._final.set()
        else:
            self._final.clear()
    final = property(_getfinal, _setfinal)
    
    def wait(self, what='final'):
        if what == 'final':
            self._final.wait()
        elif what == 'terminated':
            self._terminated.wait()
        if self.events:
            return self.events[-1]

    def armtimer(self, name, duration):
        self.timermanager.arm(duration, self.timer, name, self.state)

    def response(self, response):
        with self.lock:
            eventcb = getattr(self, '{}_{}xx'.format(self.state, response.familycode), None)
            if eventcb:
                state = self.state
                log.info("%s <-- Response %s %s", self, response.code, response.reason)
                self.events.append(response)
                eventcb()
                if self.state != state:
                    log.info(self)
                if self.state == 'Terminated':
                    self._terminated.set()

    def error(self, message):
            eventcb = getattr(self, '{}_Error'.format(self.state), None)
            if eventcb:
                log.info("%s <-- Transport error", self)
                self.events.append('transport error')
                eventcb()
                log.info(self)
                if self.state == 'Terminated':
                    self._terminated.set()

    def request(self, request):
        with self.lock:
            eventcb = getattr(self, '{}_Request'.format(self.state), None)
            if eventcb:
                eventcb()
                if self.state == 'Terminated':
                    self._terminated.set()

    def timer(self, name, state):
        with self.lock:
            if state == self.state:
                eventcb = getattr(self, '{}_Timer{}'.format(self.state, name), None)
                if eventcb:
                    log.info("%s <-- Timer %s", self, name)
                    eventcb()
                    if self.state != state:
                        log.info(self)
                    if self.state == 'Terminated':
                        self._terminated.set()

                
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
        self.events.append('time out')
        self.state = 'Terminated'
        self.final = True
    Trying_Error = Trying_TimerF

    def Trying_1xx(self):
        self.state = 'Proceeding'
        self.armtimer('E', self.T2)
        self.armtimer('F', 64*self.T1)

    def Trying_23456(self):
        self.state = 'Completed'
        self.armtimer('K', self.T4)
        self.final = True
    Trying_2xx = Trying_3xx = Trying_4xx = Trying_5xx = Trying_6xx = Trying_23456

    def Proceeding_TimerE(self):
        self.transport.send(self.request, self.addr)
        self.armtimer('E', self.T2)
        
    def Proceeding_TimerF(self):
        self.events.append('time out')
        self.state = 'Terminated'
        self.final = True
    Proceeding_Error = Proceeding_TimerF

    def Proceeding_1xx(self):
        pass

    def Proceeding_23456(self):
        self.state = 'Completed'
        self.armtimer('K', self.T4)
        self.final = True
    Proceeding_2xx = Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_23456

    def Completed_TimerK(self):
        self.state = 'Terminated'

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

    def Calling_1xx(self):
        self.state = 'Proceeding'

    def Calling_2xx(self):
        self.state = 'Terminated'
        
    def Calling_3456(self):
        self.transport.send(ack, self.addr)
        self.state = 'Completed'
        self.armtimer('D', 32)
    Calling_3xx = Calling_4xx = Calling_5xx = Calling_6xx = Calling_3456
        
    def Proceeding_1xx(self):
        pass
        
    def Proceeding_2xx(self):
        self.state = 'Terminated'
        
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



if __name__ == '__main__':
    from . import Transport
    from . import Timer

    import logging.config
    LOGGING = {
        'version': 1,
        'formatters': {
            'simple': {
                'format': "%(asctime)s %(levelname)s %(name)s %(message)s"
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'simple',
            }
        },
        'loggers': {
            'Transaction': {
                'level': 'INFO'
            },
            'Transport': {
                'level': 'ERROR'
            }
        },
        'root': {
            'handlers': ['console']
        }
    }
    logging.config.dictConfig(LOGGING)

    class UA(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self, daemon=True)
            Transport.errorcb = self.transporterror
            self.transport = Transport.Transport(Transport.get_ip_address('eno1'), listenport=5061)
            self.timermanager = Timer.TimerManager()
            self.transactions = {}
            self.start()
        def transporterror(self, err, addr, message):
            id = clientidentifier(message)
            assert(id == self.transaction.id)
            self.transaction.error(message)
        def run(self):
            while True:
                message = self.transport.recv()
                if isinstance(message, Message.SIPResponse):
                    id = clientidentifier(message)
                    assert(id in self.transactions)
                    transaction = self.transactions[id]
                    transaction.response(message)
        def newtransaction(self, request, addr):
            id = clientidentifier(request)
            transaction = ClientTransaction(request, self.transport, addr, self.timermanager, T1=.5, T2=1., T4=1.)
            self.transactions[id] = transaction
            return transaction

    ua = UA()
    req1 = Message.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    req2 = Message.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    transaction1 = ua.newtransaction(req1, '194.2.137.40')
    transaction2 = ua.newtransaction(req2, '194.2.137.40')
    print(transaction1.wait())
    print(transaction2.wait())
    transaction1.wait('terminated')
    transaction2.wait('terminated')
    
