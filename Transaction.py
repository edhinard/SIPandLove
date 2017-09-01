#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import time
import logging
log = logging.getLogger('Transaction')

from . import Message
from . import Timer

def clientidentifier(message):
    if isinstance(message, Message.SIPRequest):
        method = message.METHOD
    else:
        cseq = message.getheader('CSeq')
        if cseq:
            method = cseq.method.upper()
        else:
            method = None
    return (message.branch, method)
def serveridentifier(request):
    via = request.getheader('Via')
    if via:
        if via.port:
            sentby = "{}:{}".format(via.host, via.port)
        else:
            sentby = via.host
    else:
        sentby = None
    if isinstance(request, Message.ACK):
        method = 'INVITE'
    else:
        method = request.METHOD
    return (request.branch, sentby, method)

class Transaction:
    def __init__(self, request, transport, addr=None, *, T1, T2, T4):
        self.id = self.identifier(request)
        self.request = request
        self.transport = transport
        self.addr = addr
        self.T1 = T1
        self.T2 = T2
        self.T4 = T4
        self.lock = threading.Lock()
        self.events = []
        self.finalresponse = None
        self._final = threading.Event()
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
            if self.events and isinstance(self.events[-1], Message.SIPResponse):
                self.finalresponse = self.events[-1]
        else:
            self._final.clear()
    final = property(_getfinal, _setfinal)
    
    def wait(self):
        self._final.wait()
        if self.finalresponse:
            return self.finalresponse.code
        if self.events:
            return self.events[-1]

    def armtimer(self, name, duration):
        Timer.arm(duration, self.eventtimer, name, self.state)

    def eventresponse(self, response):
        with self.lock:
            eventcb = getattr(self, '{}_{}xx'.format(self.state, response.familycode), None)
            if eventcb:
                state = self.state
                log.info("%s <-- Response %s %s", self, response.code, response.reason)
                self.events.append(response)
                eventcb()
                if self.state != state:
                    log.info(self)

    def eventerror(self, message):
            eventcb = getattr(self, '{}_Error'.format(self.state), None)
            if eventcb:
                log.info("%s <-- Transport error", self)
                self.events.append('transport error')
                eventcb()
                log.info(self)

    def eventrequest(self, request):
        with self.lock:
            eventcb = getattr(self, '{}_Request'.format(self.state), None)
            if eventcb:
                state = self.state
                log.info("%s <-- %s", self, request.METHOD)
                self.lastrequest = request
                eventcb()
                if self.state != state:
                    log.info(self)

    def eventtimer(self, name, state):
        with self.lock:
            if state == self.state:
                eventcb = getattr(self, '{}_Timer{}'.format(self.state, name), None)
                if eventcb:
                    log.info("%s <-- Timer %s", self, name)
                    if name in ('B', 'F', 'H'):
                        self.events.append('time out')
                    eventcb()
                    if self.state != state:
                        log.info(self)

                
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
        self.final = True
    Calling_Error = Calling_TimerB

    def Calling_1xx(self):
        self.state = 'Proceeding'

    def Calling_2xx(self):
        self.state = 'Terminated'
        self.final = True
        
    def Calling_3456(self):
        self.transport.send(self.request.ack(self.events[-1]), self.addr)
        self.state = 'Completed'
        self.armtimer('D', 32)
        self.final = True
    Calling_3xx = Calling_4xx = Calling_5xx = Calling_6xx = Calling_3456
        
    def Proceeding_1xx(self):
        pass
        
    def Proceeding_2xx(self):
        self.state = 'Terminated'
        self.final = True
        
    def Proceeding_3456(self):
        self.transport.send(self.request.ack(self.events[-1]), self.addr)
        self.armtimer('D', 32)
        self.state = 'Completed'
        self.final = True
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Completed_3456(self):
        self.transport.send(self.request.ack(self.events[-1]), self.addr)
    Completed_3xx = Completed_4xx = Completed_5xx = Completed_6xx = Completed_3456

    def Completed_TimerD(self):
        self.state = 'Terminated'
        self.final = True
        
    def Calling_Error(self):
        self.state = 'Terminated'
        self.final = True

        
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
        self.final = True

        
class INVITEserverTransaction(Transaction):
    identifier = staticmethod(serveridentifier)

    def init(self):
        self.response = self.request.response(100)
        self.state = 'Proceeding'
        self.transport.send(self.response)

    def Proceeding_Request(self):
        if self.lastrequest.METHOD == 'INVITE':
            self.transport.send(self.response)
        else:
            log.warning("%s expecting INVITE. Request ignored", self)

    def Proceeding_1xx(self):
        self.response = self.events[-1]
        self.transport.send(self.response)

    def Proceeding_2xx(self):
        self.response = self.events[-1]
        self.state = 'Terminated'
        self.transport.send(self.response)

    def Proceeding_3456(self):
        self.response = self.events[-1]
        self.state = 'Completed'
        self.Gduration = self.T1
        self.armtimer('G', self.Gduration)
        self.armtimer('H', 64*self.T1)
        self.transport.send(self.response)
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Proceeding_Error(self):
        self.state = 'Terminated'

    Completed_Request = Proceeding_Request

    def Completed_TimerG(self):
        self.transport.send(self.response)
        self.Gduration = min(2*self.Gduration, self.T2)
        self.armtimer('G', self.Gduration)

    def Completed_TimerH(self):
        self.state = 'Terminated'
    Completed_Error = Completed_TimerH

    def Completed_Request(self):
        if self.lastrequest.METHOD == 'ACK':
            self.state = 'Confirmed'
            self.armtimer('I', self.T4)
        else:
            log.warning("%s expecting ACK. Request ignored", self)

    def Confirmed_TimerI(self):
        self.state = 'Terminated'
        
class NonINVITEserverTransaction(Transaction):
    identifier = staticmethod(serveridentifier)

    def init(self):
        self.response = self.request.response(100)
        self.state = 'Trying'

    def Trying_1xx(self):
        self.response = self.events[-1]
        self.state = "Proceeding"
        self.transport.send(self.response)

    def Trying_23456(self):
        self.response = self.events[-1]
        self.state = "Completed"
        self.armtimer('J', 64*self.T1)
        self.transport.send(self.response)
    Trying_2xx = Trying_3xx = Trying_4xx = Trying_5xx = Trying_6xx = Trying_23456

    def Proceeding_Request(self):
        if self.lastrequest.METHOD == self.request.METHOD:
            self.transport.send(self.response)
        else:
            log.warning("%s expecting %s. Request ignored", self, self.request.METHOD)

    def Proceeding_1xx(self):
        self.response = self.events[-1]
        self.transport.send(self.response)

    def Proceeding_Error(self):
        self.state = 'Terminated'
        
    Proceeding_2xx = Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Trying_23456

    Completed_Request = Proceeding_Request

    def Completed_TimerJ(self):
        self.state = 'Terminated'

    Completed_Error = Proceeding_Error


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
            self.transactions = {}
            self.start()
        def transporterror(self, err, addr, message):
            id = clientidentifier(message)
            assert(id == self.transaction.id)
            self.transaction.eventerror(message)
        def run(self):
            while True:
                message = self.transport.recv()
                if isinstance(message, Message.SIPResponse):
                    id = clientidentifier(message)
                    assert(id in self.transactions)
                    transaction = self.transactions[id]
                    transaction.eventresponse(message)
        def newtransaction(self, request, addr):
            id = clientidentifier(request)
            transaction = ClientTransaction(request, self.transport, addr, T1=.5, T2=4., T4=5.)
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
    time.sleep(5)
    
