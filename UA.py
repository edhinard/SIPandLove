#! /usr/bin/python3
# coding: utf-8

import multiprocessing
import threading
import random
import logging
log = logging.getLogger('UA')

from . import SIPBNF
from . import Message
from . import Transport
from . import Transaction
from . import Timer

class AuthenticationError(Exception):
    def __init__(self, reason, code=None):
        self.code = code
        self.reason = str(reason)
    def __str__(self):
        if self.code:
            return "{} {}".format(self.code, self.reason)
        return self.reason

class SIPPhone(threading.Thread):
    def __init__(self, sigtransport, proxy, uri, addressofrecord, credentials=None, codecs=None, mediaip=None, mediaport=None, T1=None, T2=None, T4=None):
        threading.Thread.__init__(self, daemon=True)
        Transport.errorcb = self.transporterror

        self.sigtransport = sigtransport
        self.proxy = proxy
        self.uri = uri
        self.addressofrecord = addressofrecord
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = transport.localip
        self.contacturi.port = transport.localport
        self.credentials = credentials
        if codecs is None:
            self.codecs = [(0,'PCMU/8000',None),
                           (8,'PCMA/8000',None)]
        else:
            self.codecs = codecs
        self.mediaip = mediaip or self.sigtransport.localip
        self.mediaport = mediaport
        self.T1 = T1 or .5
        self.T2 = T2 or 4.
        self.T4 = T4 or 5.
        self.lock = threading.Lock()
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
            transaction = transactionclass(request, self.sigtransport, T1=self.T1, T2=self.T2, T4=self.T4)
            self.transactions.append(transaction)
            return transaction            
    def newclienttransaction(self, request, addr):
        with self.lock:
            if isinstance(request, Message.INVITE):
                transactionclass = Transaction.INVITEclientTransaction
            else:
                transactionclass = Transaction.NonINVITEclientTransaction
            transaction = transactionclass(request, self.sigtransport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
            self.transactions.append(transaction)
            return transaction
    def transactionmatching(self, message):
        with self.lock:
            for transaction in self.transactions:
                if transaction.id == transaction.identifier(message):
                    return transaction
    def run(self):
        while True:
            message = self.sigtransport.recv()
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
                    newtransaction = Transaction.ACKclientTransaction(ack, self.sigtransport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
                    self.transactions.append(newtransaction)
                if isinstance(transaction, Transaction.INVITEserverTransaction) \
                   and transaction.finalresponse \
                   and transaction.finalresponse.familycode == 2:
                    response = transaction.finalresponse
                    newtransaction = Transaction.ACKserverTransaction(invite, self.sigtransport, response2xx=response, T1=self.T1, T2=self.T2, T4=self.T4)
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
        sdp = """v=0
o=- 123 123 IN IP4 172.20.35.253
s=-
m=audio 4001 RTP/AVP 8
c=IN IP4 172.20.35.253
a=rtpmap:8 PCMA/8000
"""
        return invite.response(200,
                               'Contact: {}'.format(self.contacturi),
                               'c:application/sdp',
                               self.allow,
                               body=sdp)

    def authenticate(self, message, addr):
        message.newbranch()
        message.getheader('CSeq').seq += 1
        transaction = self.newclienttransaction(message, addr)
        transaction.wait()
        if transaction.finalresponse and transaction.finalresponse.code in (401, 407):
            log.info("%s needs authentication", message.METHOD)
            auth = message.authenticationheader(transaction.finalresponse, **self.credentials)
            if auth.header is None:
                raise AuthenticationError(auth.error)
            message.replaceoraddheaders(auth.header)
            message.newbranch()
            transaction = self.newclienttransaction(message, addr)
            transaction.wait()
        if not transaction.finalresponse:
            raise transaction.lastevent
        if transaction.finalresponse.familycode != 2:
            raise AuthenticationError(transaction.finalresponse.reason, transaction.finalresponse.code)
        return transaction.finalresponse
    
    def register(self, expires=3600):
        if expires > 0:
            log.info("%s registering for %ds", self, expires)
        else:
            log.info("%s unregistering", self)
        self.reg.replaceoraddheaders('Expires: {}'.format(expires))
        try:
            finalresponse = self.authenticate(self.reg, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError) as e:
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

    def invite(self, touri, sdp):
        log.info("%s inviting %s", self, touri)
        mediatransport = Transport.MediaTransport(self.mediaip, self.mediaport)
        sdplines = ['v=0',
                    'o=- {0} {0} IN IP4 {1}'.format(random.randint(0,0xffffffff), self.mediaip),
                    's=-',
                    'm=audio {} RTP/AVP {}'.format(mediatransport.localport, ' '.join([str(t) for t,n,f in self.codecs])),
                    'c=IN IP4 {}'.format(self.mediaip),
        ] + ['a=rtpmap:{} {}'.format(t, n) for t,n,f in self.codecs if n] + ['a=fmtp:{} {}'.format(t, f) for t,n,f in self.codecs if f]
        sdp = '\r\n'.join(sdplines)

        invite = Message.INVITE(touri,
                                'From: {}'.format(self.addressofrecord),
                                'To: {}'.format(touri),
                                'Contact: {}'.format(self.contacturi),
                                self.allow,
                                'c:application/sdp',
                                body=sdp)
        try:
            finalresponse = self.authenticate(invite, self.proxy)
        except (Transaction.Timeout, Transaction.TransportError, AuthenticationError) as e:
            log.info("%s inviting failed: %s", self, e)
            return False
        log.info("invite ok")

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
    import logging.config
    LOGGING = {
        'version': 1,
        'formatters': {
            'simple': {
                'format': "%(asctime)s %(levelname)s %(name)s %(message)s"
            },
            'raw': {
                'format': "%(name)s \x1b[32;1m%(message)s\x1b[m"
            }
        },
        'handlers': {
            'console1': {
                'class': 'logging.StreamHandler',
                'formatter': 'simple',
            },
            'console2': {
                'class': 'logging.StreamHandler',
                'formatter': 'raw',
            }
        },
        'loggers': {
            'UA': {
                'level': 'INFO',
                'handlers': ['console1']
            },
            'Transaction': {
                'level': 'INFO',
                'handlers': ['console1']
            },
            'Transport': {
                'level': 'INFO',
                'handlers': ['console1']
            },
            'Message': {
                'level': 'WARNING',
                'handlers': ['console2']
            },
            'Header': {
                'level': 'WARNING',
                'handlers': ['console1']
            }
        },
    }
    logging.config.dictConfig(LOGGING)


            
    transport = Transport.SignalingTransport(Transport.get_ip_address('eno1'), 5678)
    phone = SIPPhone(transport, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821224@osk.nokims.eu', credentials=dict(username='+33900821224@osk.nokims.eu', password='nsnims2008'))

    transport2 = Transport.SignalingTransport(Transport.get_ip_address('eno1'), 5070)
    phone2 = SIPPhone(transport2, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821221@osk.nokims.eu', credentials=dict(username='+33900821221@osk.nokims.eu', password='nsnims2008'))

    ret = phone.register()
    ret = phone2.register()

    sdp = """v=0
o=- 123 123 IN IP4 172.20.35.253
s=-
m=audio 4000 RTP/AVP 8
c=IN IP4 172.20.35.253
a=rtpmap:8 PCMA/8000
"""
    ret = phone.invite('sip:+33900821221@osk.nokims.eu', sdp)
    import time
    time.sleep(30)
    
    ret = phone.register(0)
    ret = phone2.register(0)
