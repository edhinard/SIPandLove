#! /usr/bin/python3
# coding: utf-8

import multiprocessing
import threading
import logging
log = logging.getLogger('UA')

from . import SIPBNF
from . import Message
from . import Transport
from . import Transaction
from . import Timer

class UA(threading.Thread):
    def __init__(self, transport, T1, T2, T4):
        threading.Thread.__init__(self, daemon=True)
        Transport.errorcb = self.transporterror
        self.transport = transport
        self.T1 = T1
        self.T2 = T2
        self.T4 = T4
        self.lock = threading.Lock()
        self.clienttransactions = {}
        self.servertransactions = {}
        self.start()
    def transporterror(self, err, addr, message):
        idc = Transaction.clientidentifier(message)
        with self.lock:
            transaction = self.clienttransactions.get(idc)
        if not transaction:
            ids = Transaction.serveridentifier(message)
            with self.lock:
                transaction = self.servertransactions.get(ids)
        if transaction:
            transaction.error(message)
    def newservertransaction(self, request):
        with self.lock:
            transaction = Transaction.ServerTransaction(request, self.transport, T1=self.T1, T2=self.T2, T4=self.T4)
            self.servertransactions[transaction.id] = transaction
    def newclienttransaction(self, request, addr):
        with self.lock:
            transaction = Transaction.ClientTransaction(request, self.transport, addr, T1=self.T1, T2=self.T2, T4=self.T4)
            self.clienttransactions[transaction.id] = transaction
            return transaction
    def run(self):
        while True:
            message = self.transport.recv()
            if isinstance(message, Message.SIPResponse):
                id = Transaction.clientidentifier(message)
                with self.lock:
                    transaction = self.clienttransactions.get(id)
                if transaction:
                    transaction.response(message)
            elif isinstance(message, Message.SIPRequest):
                id = Transaction.serveridentifier(message)
                with self.lock:
                    transaction = self.servertransactions.get(id)
                if transaction:
                    transaction.request(message)
                else:
                    self.newservertransaction(message)
                
        

class SIPPhone(UA):
    def __init__(self, transport, proxy, uri, addressofrecord, credentials=None, T1=.5, T2=4., T4=5.):
        UA.__init__(self, transport, T1, T2, T4)
        self.proxy = proxy
        self.uri = uri
        self.addressofrecord = addressofrecord
        self.credentials = credentials
        self.registration =  []
        contacturi = SIPBNF.URI(uri)
        contacturi.host = transport.listenip
        contacturi.port = transport.listenport
        self.reg = Message.REGISTER(self.uri,
                                    'From: {}'.format(self.addressofrecord),
                                    'To: {}'.format(self.addressofrecord),
                                    'Contact: {}'.format(contacturi))

    def authenticate(self, message, addr):
        message.newbranch()
        message.getheader('CSeq').seq += 1
        transaction = self.newclienttransaction(message, addr)
        ret = transaction.wait()
        if ret in (401, 407):
            message.addauthorization(transaction.finalresponse, **self.credentials)
            message.newbranch()
            transaction = self.newclienttransaction(message, addr)
            ret = transaction.wait()
        return transaction.finalresponse
    
    def register(self, expires=3600):
        self.reg.removeheader('Expires')
        self.reg.addheaders('Expires: {}'.format(expires))
        finalresponse = self.authenticate(self.reg, self.proxy)
        if finalresponse and finalresponse.familycode == 2:
            expiresheader = finalresponse.getheader('Expires')
            if expiresheader:
                expires = expiresheader.delta
            contactheader = finalresponse.getheader('Contact')
            if contactheader:
                expires = contactheader.params.get('expires')
            print(expires)
                
            #self.registration ...
            return True
        return False

    def invite(self, sipuri, timeout):
        invite = Message.INVITE()
        ok, finalresponse = self.authenticate(invite)
        if ok:
            #self.dialog ...
            pass
        return ok

    def bye(self, dialog):
        pass

    def options(self, uri):
        pass

    def subscribe(self, contact):
        pass

    def invitationreceived(self, contact, sdp):
        return sdp or None
    
    def invited(self, sipuri, sdp):
        pass

    def notified(self, xxx):
        pass



    
if __name__ == '__main__':
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
            'UA': {
                'level': 'INFO'
            },
            'Transaction': {
                'level': 'INFO'
            },
            'Transport': {
                'level': 'ERROR'
            },
            'Message': {
                'level': 'DEBUG'
            }
        },
        'root': {
            'handlers': ['console']
        }
    }
    logging.config.dictConfig(LOGGING)

    transport = Transport.Transport(Transport.get_ip_address('eno1'))
    phone = SIPPhone(transport, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821220@osk.nokims.eu', credentials=dict(username='+33900821220@osk.nokims.eu', password='nsnims2008'))
    ret = phone.register()
    ret = phone.register(0)
    import time
    time.sleep(10)
    ret = phone.register()
