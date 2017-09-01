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
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = transport.listenip
        self.contacturi.port = transport.listenport
        self.reg = Message.REGISTER(self.uri,
                                    'From: {}'.format(self.addressofrecord),
                                    'To: {}'.format(self.addressofrecord),
                                    'Contact: {}'.format(self.contacturi))
    def __str__(self):
        return str(self.contacturi)

    def authenticate(self, message, addr):
        message.newbranch()
        message.getheader('CSeq').seq += 1
        transaction = self.newclienttransaction(message, addr)
        ret = transaction.wait()
        if ret in (401, 407):
            log.info("%s needs authentication", message.method)
            message.addauthorization(transaction.finalresponse, **self.credentials)
            message.newbranch()
            transaction = self.newclienttransaction(message, addr)
            ret = transaction.wait()
        return ret, transaction.finalresponse
    
    def register(self, expires=3600):
        if expires > 0:
            log.info("%s registering for %ds", self, expires)
        else:
            log.info("%s unregistering", self)
        self.reg.removeheader('Expires')
        self.reg.addheaders('Expires: {}'.format(expires))
        code, finalresponse = self.authenticate(self.reg, self.proxy)
        if finalresponse and finalresponse.familycode == 2:
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
        else:
            if finalresponse:
                log.info("%s (un)registering failed: %d %s", self, finalresponse.code, finalresponse.reason)
            else:
                log.info("%s (un)registering failed: %s", self, code)
            return True
        return False

    def invite(self, touri):
        log.info("%s inviting %s", self, touri)
        invite = Message.INVITE(self.uri,
                                'From: {}'.format(self.addressofrecord),
                                'To: {}'.format(touri),
                                'Contact: {}'.format(self.contacturi))
        code, finalresponse = self.authenticate(invite, self.proxy)
        if finalresponse and finalresponse.familycode == 2:
            log.info("invite ok")
        else:
            if finalresponse:
                log.info("%s inviting failed: %d %s", self, finalresponse.code, finalresponse.reason)
            else:
                log.info("%s inviting failed: %s", self, code)
            

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
                'level': 'ERROR'
            },
            'Transport': {
                'level': 'ERROR'
            },
            'Message': {
                'level': 'ERROR'
            },
            'Header': {
                'level': 'ERROR'
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

    transport2 = Transport.Transport(Transport.get_ip_address('eno1'), 5070)
    phone2 = SIPPhone(transport2, '194.2.137.40', 'sip:osk.nokims.eu', 'sip:+33900821221@osk.nokims.eu', credentials=dict(username='+33900821221@osk.nokims.eu', password='nsnims2008'))
    ret = phone2.register()

    
    ret = phone.invite('sip:+33900821221@osk.nokims.eu')
    ret = phone.register(0)
