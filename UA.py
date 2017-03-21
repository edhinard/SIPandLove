#! /usr/bin/python3
# coding: utf-8

import sys
import multiprocessing
import threading
import collections

import Message
import Transport
import Transaction
import Timer

class UA(threading.Thread):
    def __init__(self, transport=Transport.DEFAULT, T1=None, T2=None, T4=None):
        threading.Thread.__init__(self, daemon=True)
        self.transport = transport
        if self.transport is None:
            raise ValueError("No default Transport")

        self.timers = Timer.TimerManager(T1, T2, T4)

        self.newtranslock = threading.Lock()
        self.newtrans = []
        self.transactions = set()
        
        self.start()
        self.transport.ingress = self.ingress

    def newtransaction(request):
        if not issubclass(request, Message.SIPRequest):
            raise TypeError('expecting SIPRequest')
        request.transport = transport
        transaction = Transaction.ClientTransaction(request, self.timers)
        with self.newtranslock:
            self.newtrans.append(transaction)
        yield from transaction.responses()

    def ingress(self, message):
        # Processing one message from transport layer
        #  o find the transaction that the message belongs to
        #    and update transaction state with the message
        #  o if no existing transaction match:
        #     * if it is a request, create a new server transaction
        #     * if it is a 200-OK to an INVITE and the dialog exists, reply with an ACK
        # Execution context = Transport thread
        transaction = self.dispatchmessage(message)
        if transaction:
            terminated = transaction.messageinput(message)
            if terminated:
                self.transactions.remove(transaction)
        else:
            if isinstance(message, Message.SIPRequest):
                transaction = Transaction.ServerTransaction(message, self.timers)
                self.transactions.add(transaction)
                transaction.start()
            elif message.code == 200 and self.dialogxxx:
                self.message.ack().send()
                self.dialog.confirm()
    def dispatchmessage(self, message):
        if isinstance(message, Message.SIPResponse):
            for transaction in (transaction for transaction in self.transactions if isinstance(transaction, Transaction.ClientTransaction)):
                if transaction.match(message):
                    return transaction
        elif isinstance(message, Message.SIPRequest):
            for transaction in (transaction for transaction in self.transactions if isinstance(transaction, Transaction.ServerTransaction)):
                if transaction.match(message):
                    return transaction
        return None
        
    # Thread loop
    def run(self):
        while True:
            time.sleep(0.2)
            
            with self.newtranslock:
                while self.newtrans:
                    # Processing new client transactions
                    somethinghappened = True
                    transaction = self.newtrans.pop(0)
                    self.transactions.add(transaction)
                    transaction.start()
        
    
class SIPphone(UA):
    def __init__(self, transport=Transport.DEFAULT, proxy=None, uri=None, credentials=None):
        UA.__init__(self, transport)

    Registration = collections.namedtuple('Registration', "ok responses")
    def register(self, expire, headers={}, body={}):
        request = Message.REGISTER(expire=expire, headers, body)
        responses = list(self.newtransaction(request))
        finalresp = responses[-1]
        if isinstance(finalresp, Message.SIPResponse) and finalresp.code in (401, 407):
            request = finalresp.authenticate()
            responses = list(self.newtransaction(request))
            finalresp = responses[-1]
        ok = isinstance(finalresp, Message.SIPResponse) and finalresp.familycode == 2
        return SIPphone.Registration(ok, responses)

        
#        if not responses:
#            raise Exception("REGISTER transaction ends up with no response")
#        if isinstance(responses[-1], Message.SIPResponse):
#            familycode = responses[-1].familycode
#            if familycode in (0, 1) of familycode >= 7:
#                raise Exception("REGISTER transaction ends up without final response")
#                    pass
#                elif familycode == 2:
#                    pass
#                elif familycode == 3:
#                    pass
#                elif familycode == 4:
#                    pass
#                elif familycode == 5:
#                    pass
#                elif familycode == 6:
#                    pass
                    

    def invite(self, sipuri, timeout):#-> dialog
        pass

    def bye(self, dialog):
        pass

    def options(self, uri):
        pass



if __name__ == '__main__':
    phone = SIPphone(proxy='194.2.137.40', uri='sip:+33900821220@osk.nokims.eu', credentials={'username':'+33900821220@osk.nokims.eu', 'password'='nsnims2008'})
    registration = phone.register(3000, headers={})
    if registration.ok:
        call = phone.invite('+33900821221@osk.nokims.eu', timeout=5, headers={}, body=SDP())
        if call.ok:
            call.playfile(xxx)
            call.recordfile(xxx)
            sleep(15)
            call.stop()
        phone.register(0, headers={})


#    handler = phone.handleinvite()
#    phone.send()
    
#    handler = phone.handle('NOTIFY')
#    phone.send(SUBSCRIBE())
#ou
#    subscription = phone.subscribe(headers={})

        





        
#class User:
#    def __init__(self, sipuri, password=None, invitecb=None):
#        self.sipuri = sipuri
#        self.password = password
#        self.invitecb = invitecb
#        self.registered = False
#        
#    def register(self, cb=None):
#        reg = Message.REGISTER(self.sipuri)
#        m = Transaction.manager.send(reg)
#        if m.code == 401:
#            reg.authenticate(m.headers['WWW-Authenticate'], self.password)
#            m = Transaction.manager.send(reg)
#        elif m.code == 407:
#            reg.authenticate(m.headers['Proxy-Authenticate'], self.password)
#            m = Transaction.manager.send(reg)
#
#        if m.code == 200:
#            self.registered = True
#            return self
#
#        raise Exception(str(m))
#        
#    async def invite(self, to, sdp, audioin, audioout):
#        inv = Message.INVITE()
#        m = await Transaction.manager.send(reg)
#        if m.code == 401:
#            reg.authenticate(m.headers['WWW-Authenticate'], self.password)
#            m = await Transaction.manager.send(reg)
#        elif m.code == 407:
#            reg.authenticate(m.headers['Proxy-Authenticate'], self.password)
#            m = await Transaction.manager.send(reg)
#
#        if m.code == 200:
#            self.registered = True
#            return self
#
#        raise Exception(str(m))
