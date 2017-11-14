#! /usr/bin/python3
# coding: utf-8

import multiprocessing
import threading
import random
import logging
import time
log = logging.getLogger('UA')

from . import SIPBNF
from . import Message
from . import Transport
from . import Transaction
from . import Timer
from . import Media

class AuthenticationError(Exception):
    def __init__(self, message):
        self.message
    def __str__(self):
        return self.message

class Refusal(Exception):
    def __init__(self, response):
        self.code = response.code
        self.reason = response.reason
    def __str__(self):
        return "{} {}".format(self.code, self.reason)

class SIPPhone(threading.Thread):
    def __init__(self, transport, proxy, uri, addressofrecord, credentials=None, T1=None, T2=None, T4=None):
        threading.Thread.__init__(self, daemon=True)
        Transport.errorcb = self.transporterror

        self.transport = transport
        self.proxy = proxy
        self.uri = uri
        self.addressofrecord = addressofrecord
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = transport.localip
        self.contacturi.port = transport.localport
        self.credentials = credentials
        self.T1 = T1 or .5
        self.T2 = T2 or 4.
        self.T4 = T4 or 5.
        self.lock = threading.Lock()
        self.media = None
        self.transactions = []
        allow = set(('ACK',))
        for attr in dir(self):
            if attr.endswith('_handler'):
                method = attr[:-len('_handler')]
                if method == method.upper():
                    allow.add(method)
        self.allow = 'Allow: {}'.format(', '.join(allow))
        self.reg = Message.REGISTER(self.uri,
                                    'From: {}'.format(self.addressofrecord),
                                    'To: {}'.format(self.addressofrecord),
                                    'Contact: {}'.format(self.contacturi),
                                    self.allow)
        self.start()

    def __str__(self):
        return str(self.contacturi)

    def transporterror(self, err, addr, message):
        with self.lock:
            transaction = self.transactionmatching(message)
            if transaction:
                transaction.eventerror(message)
    def newservertransaction(self, request):
        with self.lock:
            if isinstance(request, Message.INVITE):
                transactionclass = Transaction.INVITEserverTransaction
            else:
                transactionclass = Transaction.NonINVITEserverTransaction
            transaction = transactionclass(request, self.transport, T1=self.T1, T2=self.T2, T4=self.T4)
            self.transactions.append(transaction)
            return transaction            
    def newclienttransaction(self, request, addr):
        with self.lock:
            if isinstance(request, Message.INVITE):
                transactionclass = Transaction.INVITEclientTransaction
            else:
                transactionclass = Transaction.NonINVITEclientTransaction
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
                if isinstance(transaction, Transaction.INVITEclientTransaction) \
                   and transaction.finalresponse \
                   and transaction.finalresponse.familycode == 2:
                    ack = transaction.request.ack(message)
                    addr = transaction.addr
                    newtransaction = Transaction.ACKclientTransaction(ack, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
                    self.transactions.append(newtransaction)
                if isinstance(transaction, Transaction.INVITEserverTransaction) \
                   and transaction.finalresponse \
                   and transaction.finalresponse.familycode == 2:
                    response = transaction.finalresponse
                    newtransaction = Transaction.ACKserverTransaction(invite, self.transport, response2xx=response, T1=self.T1, T2=self.T2, T4=self.T4)
                    self.transactions.append(newtransaction)

            else:
                if isinstance(message, Message.SIPRequest) and message.METHOD != 'ACK':
                    transaction = self.newservertransaction(message)
                    handler = getattr(self, '{}_handler'.format(message.METHOD), None)
                    if handler is None:
                        transaction.eventmessage(message.response(405, self.allow))
                    else:
                        Handler(handler, transaction, message)

    def INVITE_handler(self, invite):
        log.info("%s invited by %s", self, invite.getheader('f').address)
        if self.media is None:
            log.info("%s decline invitation", self)
            return invite.response(603, self.allow)
        self.media.setparticipantoffer(invite.body)
        self.media.transmit()
        log.info("%s accept invitation", self)
        return invite.response(200,
                               'Contact: {}'.format(self.contacturi),
                               'c:application/sdp',
                               self.allow,
                               body=self.media.localoffer)

    def BYE_handler(self, bye):
        log.info("%s byed by %s", self, bye.getheader('f').address)
        if self.media:
            self.media.stop()
        return bye.response(200)

    def authenticate(self, message, addr):
        message.newbranch()
        message.getheader('CSeq').seq += 1
        transaction = self.newclienttransaction(message, addr)
        transaction.wait()
        if transaction.finalresponse and transaction.finalresponse.code in (401, 407):
            log.info("%s %s needs authentication", self, message.METHOD)
            auth = message.authenticationheader(transaction.finalresponse, **self.credentials)
            if auth.header is None:
                raise AuthenticationError(auth.error)
            message.replaceoraddheaders(auth.header)
            message.newbranch()
            transaction = self.newclienttransaction(message, addr)
            transaction.wait()
        if not transaction.finalresponse:
            raise transaction.lastevent
        if transaction.finalresponse.code in (401, 407):
            raise AuthenticationError("{} {}".format(transaction.finalresponse.code, transaction.finalresponse.reason))
        if transaction.finalresponse.familycode != 2:
            raise Refusal(transaction.finalresponse)
        return transaction.finalresponse
    
    def options(self):
        log.info("%s querying for capabilities", self)
        options = Message.OPTIONS(self.uri,
                                  'From: {}'.format(self.addressofrecord),
                                  'To: {}'.format(self.addressofrecord),
                                  self.allow,
                                  'Content-Type: application/sdp')
        try:
            finalresponse = self.authenticate(options, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError, Refusal) as e:
            log.info("%s querying failed: %s", self, e)
            return
        log.info("%s query ok", self)

    def register(self, expires=3600):
        if expires > 0:
            log.info("%s registering for %ds", self, expires)
        else:
            log.info("%s unregistering", self)
        self.reg.replaceoraddheaders('Expires: {}'.format(expires))
        try:
            finalresponse = self.authenticate(self.reg, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError, Refusal) as e:
            log.info("%s registering failed: %s", self, e)
            return False

        expiresheader = finalresponse.getheader('Expires')
        if expiresheader:
            expires = expiresheader.delta
        contactheader = finalresponse.getheader('Contact')
        if contactheader:
            expires = contactheader.params.get('expires')
        if expires > 0:
            log.info("%s registered for %ds", self, expires)
        else:
            log.info("%s unregistered", self)
        #self.registration ...
        return True

    def invite(self, touri, *headers):
        invite = Message.INVITE(touri,
                                'From: {}'.format(self.addressofrecord),
                                'Contact: {}'.format(self.contacturi),
                                self.allow,
                                *headers)
        if self.media:
            invite.setbody(self.media.localoffer, 'application/sdp')
            log.info("%s inviting %s with SDP", self, touri)
        else:
            log.info("%s inviting %s without SDP", self, touri)

        try:
            finalresponse = self.authenticate(invite, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError, Refusal) as e:
            log.info("%s invitation failed: %s", self, e)
            return
        log.info("%s invitation ok", self)
        if self.media:
            self.media.setparticipantoffer(finalresponse.body)
            self.media.transmit()

        dialog = Dialog(callid = invite.getheader('call-id').callid,
                        localtag = invite.fromtag,
                        remotetag = finalresponse.totag,
                        localtarget = invite.getheader('contact').address,
                        remotetarget = finalresponse.getheader('contact').address,
                        localseq = invite.getheader('CSeq').seq,
                        remoteseq = finalresponse.getheader('CSeq').seq
                        )
        return dialog

    def bye(self, dialog):
        log.info("%s bying %s", self, dialog)
        dialog.localseq += 1
        bye = Message.BYE(dialog.remotetarget,
                         'to:{};tag={}'.format(dialog.remotetarget, dialog.remotetag),
                         'from:{};tag={}'.format(dialog.localtarget, dialog.localtag),
                         'call-id:{}'.format(dialog.callid),
                         'cesq: {} BYE'.format(dialog.localseq))
        try:
            finalresponse = self.authenticate(bye, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError, Refusal) as e:
            log.info("%s bying failed: %s", self, e)
            return
        self.media.stop()
        log.info("%s bying ok", self)

    def setmedia(self, rtpfile, mediaip=None, mediaport=None):
        self.media = Media.Media(mediaip or self.transport.localip, mediaport, rtpfile, owner=self.transport.localip)
        return self.media

class Dialog:
    def __init__(self, callid, localtag, remotetag, localtarget, remotetarget,localseq, remoteseq):
        self.callid = callid
        self.localtag = localtag
        self.remotetag = remotetag
        self.localtarget = localtarget
        self.remotetarget = remotetarget
        self.localseq = localseq
        self.remoteseq = remoteseq

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
            self.transaction.eventmessage(response)



    
if __name__ == '__main__':
    import snl
    snl.loggers['UA'].setLevel('INFO')
    snl.loggers['Transaction'].setLevel('INFO')
    snl.loggers['Transport'].setLevel('INFO')

            
    transport1 = snl.Transport('eno1', 5555)
    phone1 = snl.SIPPhone(transport1, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821224@osk.nokims.eu', credentials=dict(username='+33900821224@osk.nokims.eu', password='nsnims2008'))
#    phone1 = SIPPhone(transport1, '172.20.56.7', 'sip:sip.osk.com', 'sip:+33960700011@sip.osk.com', credentials=dict(username='+33960700011@sip.osk.com', password='huawei'))
    phone1.register()
    phone1.setmedia(Media.RTPRandomStream(PT=10, rtplen=40))

    transport2 = snl.Transport('eno1', 6666)
    phone2 = snl.SIPPhone(transport2, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821221@osk.nokims.eu', credentials=dict(username='+33900821221@osk.nokims.eu', password='nsnims2008'))
#    phone2 = SIPPhone(transport2, '172.20.56.7', 'sip:sip.osk.com', 'sip:+33960700012@sip.osk.com', credentials=dict(username='+33960700012@sip.osk.com', password='huawei'))
    phone2.register()
    with open('toto', 'w') as f:
        f.write("PT=0\nseq=0x100\n<<<<0123>>>><<<<4567>>>><<<<0123>>>><<<<4567>>>><<<<0123>>>><<<<4567>>>><<<<0123>>>><<<<4567>>>>")
    media = phone2.setmedia('toto')
    
    phone1.invite('sip:+33900821221@osk.nokims.eu')
    media.wait()

    ret = phone1.register(0)
    ret = phone2.register(0)
