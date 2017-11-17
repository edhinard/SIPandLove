#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import logging
log = logging.getLogger('Transaction')

from . import Message
from . import Timer
from . import Transport
import snl

class TransactionManager(threading.Thread):
    def __init__(self, transport, T1=None, T2=None, T4=None):
        threading.Thread.__init__(self, daemon=True)
        Transport.errorcb = self.transporterror

        if isinstance(transport, snl.Transport):
            self.transport = transport
        else:
            self.transport = snl.Transport(transport)
        self.T1 = T1 or .5
        self.T2 = T2 or 4.
        self.T4 = T4 or 5.
        self.lock = threading.Lock()
        self.transactions = []
        self.allow = set()
        for attr in dir(self):
            if attr.endswith('_handler'):
                method = attr[:-len('_handler')]
                if method == method.upper():
                    self.allow.add(method)
        if 'INVITE' in self.allow:
            self.allow.add('ACK')
        self.start()

    def transporterror(self, err, addr, message):
        with self.lock:
            transaction = self.transactionmatching(message)
            if transaction:
                transaction.eventerror(message)

    def newservertransaction(self, request):
        with self.lock:
            if isinstance(request, Message.INVITE):
                transactionclass = INVITEserverTransaction
            else:
                transactionclass = NonINVITEserverTransaction
            transaction = transactionclass(request, self.transport, T1=self.T1, T2=self.T2, T4=self.T4)
            self.transactions.append(transaction)
            return transaction

    def newclienttransaction(self, request, addr):
        with self.lock:
            if isinstance(request, Message.INVITE):
                transactionclass = INVITEclientTransaction
            else:
                transactionclass = NonINVITEclientTransaction
            if request.METHOD not in ('ACK', 'CANCEL') and self.allow:
                request.addheaders(
                    'Allow: {}'.format(', '.join(self.allow)),
                    ifabsent=True
                )
            transaction = transactionclass(request, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
            self.transactions.append(transaction)
            return transaction

    def transactionmatching(self, message):
        with self.lock:
            for transaction in self.transactions:
                if transaction.id == transaction.identifier(message):
                    return transaction
    def run(self):
        while True:
            message = self.transport.recv()
            transaction = self.transactionmatching(message)
            if transaction:
                transaction.eventmessage(message)
                if transaction.terminated:
                    self.transactions.remove(transaction)
                if isinstance(transaction, INVITEclientTransaction) \
                   and transaction.finalresponse \
                   and transaction.finalresponse.familycode == 2:
                    ack = transaction.request.ack(message)
                    addr = transaction.addr
                    newtransaction = ACKclientTransaction(ack, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
                    self.transactions.append(newtransaction)
                if isinstance(transaction, INVITEserverTransaction) \
                   and transaction.finalresponse \
                   and transaction.finalresponse.familycode == 2:
                    response = transaction.finalresponse
                    newtransaction = ACKserverTransaction(invite, self.transport, response2xx=response, T1=self.T1, T2=self.T2, T4=self.T4)
                    self.transactions.append(newtransaction)

            else:
                if isinstance(message, Message.SIPRequest) and message.METHOD != 'ACK':
                    transaction = self.newservertransaction(message)
                    handler = getattr(self, '{}_handler'.format(message.METHOD), None)
                    if handler is None:
                        response = message.response(405)
                        if self.allow:
                            response.addheaders(
                                'Allow: {}'.format(', '.join(self.allow))
                            )
                        transaction.eventmessage(response)
                    else:
                        Handler(handler, transaction, message)

class Handler(threading.Thread):
    def __init__(self, handler, transaction, request):
        threading.Thread.__init__(self, daemon=True)
        self.handler = handler
        self.transaction = transaction
        self.request = request
        self.start()
    def run(self):
        response = self.handler(self.request)
        if response:
            if response.CseqMETHOD not in ('ACK', 'CANCEL') and self.allow:
                response.addheaders(
                    'Allow: {}'.format(', '.join(self.allow)),
                    ifabsent=True
                )
            self.transaction.eventmessage(response)

class Timeout(Exception):
    pass
class TransportError(Exception):
    pass

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
        self.lastrequest = self.lastresponse = self.lastevent = None
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
            if self.lastevent == self.lastresponse and self.lastresponse.familycode > 1:
                self.finalresponse = self.lastresponse
        else:
            self._final.clear()
    final = property(_getfinal, _setfinal)

    def _getterminated(self):
        return self.state == 'Terminated'
    terminated = property(_getterminated)
    
    def wait(self):
        self._final.wait()

    def armtimer(self, name, duration):
        Timer.arm(duration, self.eventtimer, name, self.state)

    def eventmessage(self, message):
        with self.lock:
            response = request = None
            if isinstance(message, Message.SIPResponse):
                response = message
                eventcb = getattr(self, '{}_{}xx'.format(self.state, response.familycode), None)
            else:
                request = message
                eventcb = getattr(self, '{}_Request'.format(self.state), None)
            if eventcb:
                state = self.state
                if response:
                    log.info("%s <-- Response %s %s", self, message.code, message.reason)
                    self.lastresponse = response
                if request:
                    log.info("%s <-- %s", self, request.METHOD)
                    self.lastrequest = request
                self.lastevent = message
                eventcb()
                if self.state != state:
                    log.info(self)

    def eventerror(self, message):
        with self.lock:
            eventcb = getattr(self, '{}_Error'.format(self.state), None)
            if eventcb:
                log.info("%s <-- Transport error", self)
                self.lastevent = TransportError()
                eventcb()
                log.info(self)

    def eventtimer(self, name, state):
        with self.lock:
            if state == self.state:
                eventcb = getattr(self, '{}_Timer{}'.format(self.state, name), None)
                if eventcb:
                    log.info("%s <-- Timer %s", self, name)
                    if name in ('B', 'F', 'H'):
                        self.lastevent = Timeout()
                    eventcb()
                    if self.state != state:
                        log.info(self)

class ClientTransaction(Transaction):
    @staticmethod
    def identifier(message):
        if isinstance(message, Message.SIPRequest):
            method = message.METHOD
        else:
            cseq = message.getheader('CSeq')
            if cseq:
                method = cseq.method.upper()
            else:
                method = None
        return (message.branch, method)

class ServerTransaction(Transaction):
    @staticmethod
    def identifier(request):
        if isinstance(request, Message.SIPResponse):
            return
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

#                               |INVITE from TU
#             Timer A fires     |INVITE sent
#             Reset A,          V                      Timer B fires
#             INVITE sent +-----------+                or Transport Err.
#               +---------|           |---------------+inform TU
#               |         |  Calling  |               |
#               +-------->|           |-------------->|
#                         +-----------+ 2xx           |
#                            |  |       2xx to TU     |
#                            |  |1xx                  |
#    300-699 +---------------+  |1xx to TU            |
#   ACK sent |                  |                     |
#resp. to TU |  1xx             V                     |
#            |  1xx to TU  -----------+               |
#            |  +---------|           |               |
#            |  |         |Proceeding |-------------->|
#            |  +-------->|           | 2xx           |
#            |            +-----------+ 2xx to TU     |
#            |       300-699    |                     |
#            |       ACK sent,  |                     |
#            |       resp. to TU|                     |
#            |                  |                     |      NOTE:
#            |  300-699         V                     |
#            |  ACK sent  +-----------+Transport Err. |  transitions
#            |  +---------|           |Inform TU      |  labeled with
#            |  |         | Completed |-------------->|  the event
#            |  +-------->|           |               |  over the action
#            |            +-----------+               |  to take
#            |              ^   |                     |
#            |              |   | Timer D fires       |
#            +--------------+   | -                   |
#                               |                     |
#                               V                     |
#                         +-----------+               |
#                         |           |               |
#                         | Terminated|<--------------+
#                         |           |
#                         +-----------+
#
#                 Figure 5: INVITE client transaction
class INVITEclientTransaction(ClientTransaction):
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
        self.transport.send(self.request.ack(self.lastevent), self.addr)
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
        self.transport.send(self.request.ack(self.lastevent), self.addr)
        self.armtimer('D', 32)
        self.state = 'Completed'
        self.final = True
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Completed_3456(self):
        self.transport.send(self.request.ack(self.lastevent), self.addr)
    Completed_3xx = Completed_4xx = Completed_5xx = Completed_6xx = Completed_3456

    def Completed_TimerD(self):
        self.state = 'Terminated'
        self.final = True
        
    def Calling_Error(self):
        self.state = 'Terminated'
        self.final = True

#                               |ACK from TU
#                               |ACK sent
#               2xx             V
#               ACK sent  +-----------+
#               +---------|           |------------------+
#               |         |Proceeding | Timer B fires    |
#               +-------->|           | or Transport Err.|
#                         +-----------+                  |
#                                                        |
#                         +-----------+                  |
#                         |           |                  |
#                         | Terminated|<-----------------+
#                         |           |
#                         +-----------+
class ACKclientTransaction(ClientTransaction):
    def init(self):
        self.transport.send(self.request, self.addr)
        self.state = 'Proceeding'
        self.armtimer('B', 64*self.T1)

    def Proceeding_TimerB(self):
        self.state = 'Terminated'
        self.final = True
    Proceeding_Error = Proceeding_TimerB

    def Proceeding_2xx(self):
        self.transport.send(self.request, self.addr)

#                                   |Request from TU
#                                   |send request
#               Timer E             V
#               send request  +-----------+
#                   +---------|           |-------------------+
#                   |         |  Trying   |  Timer F          |
#                   +-------->|           |  or Transport Err.|
#                             +-----------+  inform TU        |
#                200-699         |  |                         |
#                resp. to TU     |  |1xx                      |
#                +---------------+  |resp. to TU              |
#                |                  |                         |
#                |   Timer E        V       Timer F           |
#                |   send req +-----------+ or Transport Err. |
#                |  +---------|           | inform TU         |
#                |  |         |Proceeding |------------------>|
#                |  +-------->|           |-----+             |
#                |            +-----------+     |1xx          |
#                |              |      ^        |resp to TU   |
#                | 200-699      |      +--------+             |
#                | resp. to TU  |                             |
#                |              |                             |
#                |              V                             |
#                |            +-----------+                   |
#                |            |           |                   |
#                |            | Completed |                   |
#                |            |           |                   |
#                |            +-----------+                   |
#                |              ^   |                         |
#                |              |   | Timer K                 |
#                +--------------+   | -                       |
#                                   |                         |
#                                   V                         |
#             NOTE:           +-----------+                   |
#                             |           |                   |
#         transitions         | Terminated|<------------------+
#         labeled with        |           |
#         the event           +-----------+
#         over the action
#         to take
#
#                 Figure 6: non-INVITE client transaction
class NonINVITEclientTransaction(ClientTransaction):
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

#                               |INVITE
#                               |pass INV to TU
#            INVITE             V send 100 if TU won't in 200ms
#            send response+-----------+
#                +--------|           |--------+101-199 from TU
#                |        | Proceeding|        |send response
#                +------->|           |<-------+
#                         |           |          Transport Err.
#                         |           |          Inform TU
#                         |           |--------------->+
#                         +-----------+                |
#            300-699 from TU |     |2xx from TU        |
#            send response   |     |send response      |
#                            |     +------------------>+
#                            |                         |
#            INVITE          V          Timer G fires  |
#            send response+-----------+ send response  |
#                +--------|           |--------+       |
#                |        | Completed |        |       |
#                +------->|           |<-------+       |
#                         +-----------+                |
#                            |     |                   |
#                        ACK |     |                   |
#                        -   |     +------------------>+
#                            |        Timer H fires    |
#                            V        or Transport Err.|
#                         +-----------+  Inform TU     |
#                         |           |                |
#                         | Confirmed |                |
#                         |           |                |
#                         +-----------+                |
#                               |                      |
#                               |Timer I fires         |
#                               |-                     |
#                               |                      |
#                               V                      |
#                         +-----------+                |
#                         |           |                |
#                         | Terminated|<---------------+
#                         |           |
#                         +-----------+
#
#              Figure 7: INVITE server transaction
class INVITEserverTransaction(ServerTransaction):
    def init(self):
        self.lastresponse = self.request.response(100)
        self.state = 'Proceeding'
        self.transport.send(self.lastresponse)

    def Proceeding_Request(self):
        if self.lastrequest.METHOD == 'INVITE':
            self.transport.send(self.lastresponse)
        else:
            log.warning("%s expecting INVITE. Request ignored", self)

    def Proceeding_1xx(self):
        self.transport.send(self.lastresponse)

    def Proceeding_2xx(self):
        self.state = 'Terminated'
        self.transport.send(self.lastresponse)

    def Proceeding_3456(self):
        self.state = 'Completed'
        self.Gduration = self.T1
        self.armtimer('G', self.Gduration)
        self.armtimer('H', 64*self.T1)
        self.transport.send(self.lastresponse)
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Proceeding_Error(self):
        self.state = 'Terminated'

    Completed_Request = Proceeding_Request

    def Completed_TimerG(self):
        self.transport.send(self.lastresponse)
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

#                               |INVITE + 2xx
#                               |
#                               V       Timer G fires
#                         +-----------+ send 2xx
#                         |           |--------+
#                         | Completed |        |
#                         |           |<-------+
#                         +-----------+
#                            |     |
#                        ACK |     |  Timer H fires
#                        -   |     |  -
#                            V     V 
#                         +-----------+
#                         |           |
#                         | Terminated|
#                         |           |
#                         +-----------+

class ACKserverTransaction(ServerTransaction):
    def __init__(self, *args, response2xx, **kwargs):
        Transaction.__init__(self, *args, **kwargs)
        self.lastresponse = response2xx

    def init(self):
        self.state = 'Completed'
        self.Gduration = self.T1
        self.armtimer('G', self.Gduration)
        self.armtimer('H', 64*self.T1)

    def Completed_TimerG(self):
        self.transport.send(self.lastresponse)
        self.Gduration = min(2*self.Gduration, self.T2)
        self.armtimer('G', self.Gduration)

    def Completed_TimerH(self):
        self.state = 'Terminated'
        self.final = True

    def Completed_Request(self):
        if self.lastrequest.METHOD == 'ACK':
            self.state = 'Terminated'
            self.final = True
        else:
            log.warning("%s expecting ACK. Request ignored", self)


#                                  |Request received
#                                  |pass to TU
#                                  V
#                            +-----------+
#                            |           |
#                            | Trying    |-------------+
#                            |           |             |
#                            +-----------+             |200-699 from TU
#                                  |                   |send response
#                                  |1xx from TU        |
#                                  |send response      |
#                                  |                   |
#               Request            V      1xx from TU  |
#               send response+-----------+send response|
#                   +--------|           |--------+    |
#                   |        | Proceeding|        |    |
#                   +------->|           |<-------+    |
#            +<--------------|           |             |
#            |Trnsprt Err    +-----------+             |
#            |Inform TU            |                   |
#            |                     |                   |
#            |                     |200-699 from TU    |
#            |                     |send response      |
#            |  Request            V                   |
#            |  send response+-----------+             |
#            |      +--------|           |             |
#            |      |        | Completed |<------------+
#            |      +------->|           |
#            +<--------------|           |
#            |Trnsprt Err    +-----------+
#            |Inform TU            |
#            |                     |Timer J fires
#            |                     |-
#            |                     |
#            |                     V
#            |               +-----------+
#            |               |           |
#            +-------------->| Terminated|
#                            |           |
#                            +-----------+
#
#                Figure 8: non-INVITE server transaction
class NonINVITEserverTransaction(ServerTransaction):
    def init(self):
        self.state = 'Trying'

    def Trying_1xx(self):
        self.state = "Proceeding"
        self.transport.send(self.lastresponse)

    def Trying_23456(self):
        self.state = "Completed"
        self.armtimer('J', 64*self.T1)
        self.transport.send(self.lastresponse)
    Trying_2xx = Trying_3xx = Trying_4xx = Trying_5xx = Trying_6xx = Trying_23456

    def Proceeding_Request(self):
        if self.lastrequest.METHOD == self.request.METHOD:
            self.transport.send(self.lastresponse)
        else:
            log.warning("%s expecting %s. Request ignored", self, self.request.METHOD)

    def Proceeding_1xx(self):
        self.transport.send(self.lastresponse)

    def Proceeding_Error(self):
        self.state = 'Terminated'
        
    Proceeding_2xx = Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Trying_23456

    Completed_Request = Proceeding_Request

    def Completed_TimerJ(self):
        self.state = 'Terminated'

    Completed_Error = Proceeding_Error


if __name__ == '__main__':
    import time
    import snl
    snl.loggers['Transaction'].setLevel('INFO')

    tm = TransactionManager(snl.Transport('eno1', localport=5061))
    req1 = snl.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    req2 = snl.REGISTER('sip:osk.nokims.eu',
                            'From:sip:+33900821220@osk.nokims.eu',
                            'To:sip:+33900821220@osk.nokims.eu')
    transaction1 = tm.newclienttransaction(req1, '194.2.137.40')
    transaction2 = tm.newclienttransaction(req2, '194.2.137.40')
    print(transaction1.wait())
    print(transaction2.wait())
    time.sleep(5)
    
