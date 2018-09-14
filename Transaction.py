#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import logging
log = logging.getLogger('Transaction')

from . import Message
from . import Timer
from . import Transport
from . import Dialog
from . import Tags

class TransactionManager(threading.Thread):
    modifybeforesend = None
    modifyafterreceive = None
    def __init__(self, transport, T1=None, T2=None, T4=None):
        threading.Thread.__init__(self, daemon=True)
        self.transport = Transport(**transport, errorcb=self.transporterror, sendcb=self.modifybeforesend, recvcb=self.modifyafterreceive)
        self.T1 = T1 or .5
        self.T2 = T2 or 4.
        self.T4 = T4 or 5.
        self.lock = threading.Lock()
        self.transactions = []
        self.ackwaiter = ACKWaiter(self.transport, self.T1, self.T2)
        self.allow = set()
        for attr in dir(self):
            if attr.endswith('_handler'):
                method = attr[:-len('_handler')]
                if method == method.upper():
                    self.allow.add(method)
        if 'INVITE' in self.allow:
            self.allow.add('ACK')
        self.start()

    def destroy(self):
        self.transport.stop()
        del self.transport
        # not enough to free self.transport since pending transactions and pending transaction timers have a reference on it...

    def transporterror(self, message, err):
        transaction = self.transactionmatching(message)
        if transaction:
            transaction.eventerror(err)

    def newservertransaction(self, request):
        if isinstance(request, Message.INVITE):
            transactionclass = INVITEserverTransaction
        else:
            transactionclass = NonINVITEserverTransaction
        transaction = transactionclass(request, self.transport, T1=self.T1, T2=self.T2, T4=self.T4)
        with self.lock:
            self.transactions.append(transaction)
        return transaction

    def newclienttransaction(self, request, addr):
        request.enforceheaders()
        if isinstance(request, Message.INVITE):
            transactionclass = INVITEclientTransaction
        else:
            transactionclass = NonINVITEclientTransaction
        if request.METHOD not in ('ACK', 'CANCEL') and self.allow:
            request.addheaders(
                'Allow: {}'.format(', '.join(self.allow)),
                ifmissing=True
            )
        transaction = transactionclass(request, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
        with self.lock:
            self.transactions.append(transaction)
        return transaction

    def transactionmatching(self, message, matchonbranch=False):
        with self.lock:
            for transaction in self.transactions:
                # "normal" match algorithm
                if not matchonbranch and (transaction.id == transaction.identifier(message)):
                    return transaction

                # used to find a transaction to CANCEL
                if matchonbranch and (transaction.request.branch == message.branch):
                    return transaction

    def run(self):
        while True:
            message = self.transport.recv()
            if message is None: # happens when transport process is terminated
                break
            transaction = self.transactionmatching(message)
            if transaction:
                transaction.eventmessage(message)
                if transaction.terminated:
                    with self.lock:
                        self.transactions.remove(transaction)
                if isinstance(transaction, INVITEclientTransaction) \
                   and transaction.lastresponse \
                   and transaction.lastresponse.familycode == 2:
                    ack = transaction.request.ack(message)
                    addr = transaction.addr
                    newtransaction = ACKclientTransaction(ack, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
                    with self.lock:
                        self.transactions.append(newtransaction)
            else:
                if isinstance(message, Message.SIPResponse):
                    pass
                elif message.METHOD != 'ACK':
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
                        Handler(self, handler, transaction, message)
                else:
                    ack = message
                    self.ackwaiter.arrived(ack)

            with self.lock:
                self.transactions = [transaction for transaction in self.transactions if not transaction.terminated]

class ACKWaiter():
    # Class responsible for 200-OK (on INVITE) retransmission until ACK is received
    def __init__(self, transport, T1, T2):
        self.transport = transport
        self.T1 = T1
        self.initialcounter = 0
        while 2**(self.initialcounter+1) - 1 < T2/self.T1:
            self.initialcounter += 1
        self.responses = {}
        self.lock = threading.Lock()

    def new(self, inviteokresponse):
        # A 200 OK response to an INVITE was just send
        #  * keep it indexed by dialog ID
        #  * arm a T1 timer to send it again
        dialogid = Dialog.UASid(inviteokresponse)
        with self.lock:
            self.responses[dialogid] = inviteokresponse

        if self.initialcounter:
            Timer.arm(self.T1, self.resend, **dict(dialogid=dialogid, delay=self.T1, counter=self.initialcounter))

    def arrived(self, ack):
        # An ACK has arrived
        #  * find the associated response and forget it
        dialogid = Dialog.UASid(ack)
        with self.lock:
            response = self.responses.pop(dialogid, None)

    def resend(self, dialogid, delay, counter):
        # It is time to send the response again
        #  * find the associated response
        #  * if absent (the ACK already arrived or we already give up)
        #       * do nothing
        #    else (the response is still here)
        #       * send the response again
        #       * if it is enough
        #            * give up i.e. forget the response
        #         else
        #            * arm another timer with double delay
        with self.lock:
            response = self.responses.get(dialogid)

        if response is not None:
            self.transport.send(response)

            delay *= 2
            counter -= 1
            if counter:
                Timer.arm(delay, self.resend, **dict(dialogid=dialogid, delay=delay, counter=counter))
            else:
                with self.lock:
                    self.responses.pop(dialogid, None)


class Handler(threading.Thread):
    def __init__(self, transactionmanager, handler, transaction, request):
        threading.Thread.__init__(self, daemon=True)
        self.transactionmanager = transactionmanager
        self.allow = transactionmanager.allow
        self.handler = handler
        self.transaction = transaction
        self.request = request
        self.start()
    def run(self):
        response = self.handler(self.request)
        if response is not None:
            if response.CseqMETHOD not in ('ACK', 'CANCEL') and self.allow:
                response.addheaders(
                    'Allow: {}'.format(', '.join(self.allow)),
                    ifmissing=True
                )
            self.transaction.eventmessage(response)
            if isinstance(self.request, Message.INVITE) and response.familycode == 2:
                self.transactionmanager.ackwaiter.new(response)

class Timeout(Exception):
    def __init__(self, timer):
        self.timer = timer
    def __str__(self):
        return "Timer {} fired".format(self.timer)

class TransportError(Exception):
    def __init__(self, error):
        self.error = error
    def __str__(self):
        return "Transport error: {}".format(self.error)

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
        self.lastrequest = self.lastresponse = None
        self.events = []
        self.eventsemaphore = threading.Semaphore(0)
        log.info("%s <-- New transaction", self)
        with self.lock:
            self.init()

    def __str__(self):
        return "{}-{}".format("/".join(self.id), self.state)

    def _getterminated(self):
        return self.state == 'Terminated'
    terminated = property(_getterminated)

    def wait(self):
        self.eventsemaphore.acquire()
        with self.lock:
            event = self.events.pop(0)
        return event

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
                if response is not None:
                    log.info("%s <-- Response %s %s", self, message.code, message.reason)
                    self.lastresponse = response
                if request is not None:
                    log.info("%s <-- %s", self, request.METHOD)
                    self.lastrequest = request
                informTU = eventcb()
                if informTU:
                    self.events.append(message)
                    self.eventsemaphore.release()
                self.checkstate(state)

    def eventerror(self, err):
        with self.lock:
            eventcb = getattr(self, '{}_Error'.format(self.state), None)
            if eventcb:
                state = self.state
                error = TransportError(err)
                log.info("%s <-- %s", self, error)
                informTU = eventcb()
                if informTU:
                    self.events.append(error)
                    self.eventsemaphore.release()
                self.checkstate(state)

    def eventtimer(self, name, state):
        with self.lock:
            if state == self.state:
                eventcb = getattr(self, '{}_Timer{}'.format(self.state, name), None)
                if eventcb:
                    log.info("%s <-- Timer %s", self, name)
                    informTU = eventcb()
                    if informTU:
                        self.events.append(Timeout(name))
                        self.eventsemaphore.release()
                    self.checkstate(state)

    def eventcancel(self):
        with self.lock:
            eventcb = getattr(self, '{}_Cancel'.format(self.state), None)
            if eventcb:
                state = self.state
                log.info("%s <-- Cancel", self)
                eventcb()
                self.checkstate(state)
                return self.lastresponse.totag

    def checkstate(self, previous):
        if self.state != previous:
            log.info(self)
            if self.state == 'Terminated':
                self.events.append(None)
                self.eventsemaphore.release()

class ClientTransaction(Transaction):
    @staticmethod
    def identifier(message):
        if isinstance(message, Message.SIPRequest):
            method = message.METHOD
        else:
            cseq = message.header('CSeq')
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
        via = request.header('Via')
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
    state = 'Calling'
    def init(self):
        self.transport.send(self.request, self.addr)
        self.Aduration = self.T1
        self.armtimer('A', self.Aduration)
        self.armtimer('B', 64*self.T1)

    def Calling_TimerA(self):
        self.transport.send(self.request, self.addr)
        self.Aduration *= 2
        self.armtimer('A', self.Aduration)

    def Calling_TimerB(self):
        self.state = 'Terminated'
        return True
    Calling_Error = Calling_TimerB

    def Calling_1xx(self):
        self.state = 'Proceeding'
        return True

    def Calling_2xx(self):
        self.state = 'Terminated'
        return True

    def Calling_3456(self):
        self.transport.send(self.request.ack(self.lastresponse), self.addr)
        self.state = 'Completed'
        self.armtimer('D', 32)
        return True
    Calling_3xx = Calling_4xx = Calling_5xx = Calling_6xx = Calling_3456

    def Proceeding_1xx(self):
        return True

    def Proceeding_2xx(self):
        self.state = 'Terminated'
        return True

    def Proceeding_3456(self):
        self.transport.send(self.request.ack(self.lastresponse), self.addr)
        self.armtimer('D', 32)
        self.state = 'Completed'
        return True
    Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_3456

    def Completed_3456(self):
        self.transport.send(self.request.ack(self.lastresponse), self.addr)
    Completed_3xx = Completed_4xx = Completed_5xx = Completed_6xx = Completed_3456

    def Completed_TimerD(self):
        self.state = 'Terminated'

    def Completed_Error(self):
        self.state = 'Terminated'
        return True

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
    @staticmethod
    def identifier(message):
        ident = ClientTransaction.identifier(message)
        if ident[-1] == 'INVITE':
            return (*ident[:-1], 'ACK')
        return ident
    state = 'Proceeding'
    def init(self):
        self.request.branch = Tags.branch()
        self.transport.send(self.request, self.addr)
        self.armtimer('B', 64*self.T1)

    def Proceeding_TimerB(self):
        self.state = 'Terminated'
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
    state = 'Trying'
    def init(self):
        self.transport.send(self.request, self.addr)
        self.Eduration = self.T1
        self.armtimer('E', self.Eduration)
        self.armtimer('F', 64*self.T1)

    def Trying_TimerE(self):
        self.transport.send(self.request, self.addr)
        self.Eduration = min(2*self.Eduration, self.T2)
        self.armtimer('E', self.Eduration)

    def Trying_TimerF(self):
        self.state = 'Terminated'
        return True
    Trying_Error = Trying_TimerF

    def Trying_1xx(self):
        self.state = 'Proceeding'
        self.armtimer('E', self.T2)
        self.armtimer('F', 64*self.T1)
        return True

    def Trying_23456(self):
        self.state = 'Completed'
        self.armtimer('K', self.T4)
        return True
    Trying_2xx = Trying_3xx = Trying_4xx = Trying_5xx = Trying_6xx = Trying_23456

    def Proceeding_TimerE(self):
        self.transport.send(self.request, self.addr)
        self.armtimer('E', self.T2)

    def Proceeding_TimerF(self):
        self.state = 'Terminated'
        return True
    Proceeding_Error = Proceeding_TimerF

    def Proceeding_1xx(self):
        return True

    def Proceeding_23456(self):
        self.state = 'Completed'
        self.armtimer('K', self.T4)
        return True
    Proceeding_2xx = Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Proceeding_23456

    def Completed_TimerK(self):
        self.state = 'Terminated'

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
    state = 'Proceeding'
    def init(self):
        self.armtimer('TryingDelay', 0.1)

    def Proceeding_TimerTryingDelay(self):
        if not self.lastresponse:
            self.lastresponse = self.request.response(100)
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
        return True

    def Proceeding_Cancel(self):
        self.lastresponse = self.request.response(487)
        self.transport.send(self.lastresponse)
        self.state = 'Completed'

    Completed_Request = Proceeding_Request

    def Completed_TimerG(self):
        self.transport.send(self.lastresponse)
        self.Gduration = min(2*self.Gduration, self.T2)
        self.armtimer('G', self.Gduration)

    def Completed_TimerH(self):
        self.state = 'Terminated'
        return True
    Completed_Error = Completed_TimerH

    def Completed_Request(self):
        if self.lastrequest.METHOD == 'ACK':
            self.state = 'Confirmed'
            self.armtimer('I', self.T4)
        else:
            log.warning("%s expecting ACK. Request ignored", self)

    def Confirmed_TimerI(self):
        self.state = 'Terminated'

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
    state = 'Trying'
    def init(self):
        pass

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
        return True
        
    Proceeding_2xx = Proceeding_3xx = Proceeding_4xx = Proceeding_5xx = Proceeding_6xx = Trying_23456

    Completed_Request = Proceeding_Request

    def Completed_TimerJ(self):
        self.state = 'Terminated'

    Completed_Error = Proceeding_Error


if __name__ == '__main__':
    import time
    import snl
    snl.loggers['Transaction'].setLevel('INFO')

    tm = TransactionManager('eno1', localport=5061)
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
    
