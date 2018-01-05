#! /usr/bin/python3
# coding: utf-8

import random
import logging
import time
import threading
log = logging.getLogger('UA')

from . import SIPBNF
from . import Message
from . import Transaction
from . import Media
from . import Timer
from . import Dialog

class UAbase(Transaction.TransactionManager):
    def __init__(self, transport, proxy, domain, addressofrecord, T1=None, T2=None, T4=None, **kwargs):
        super().__init__(transport, T1, T2, T4)

        self.proxy = proxy
        self.domain = domain
        self.addressofrecord = addressofrecord
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = self.transport.localip
        self.contacturi.port = self.transport.localport

        # call init function of mixins, in reverse MRO and only once
        called = set()
        for klass in reversed(self.__class__.mro()):
            if hasattr(klass, 'mixininit') and not klass.mixininit in called:
                kwargs = klass.mixininit(self, **kwargs)
                called.add(klass.mixininit)
        if kwargs:
            log.warning("got unexpected keyword argument {!r}".format(tuple(kwargs.keys())))

    def __str__(self):
        return str(self.contacturi)

    def sendmessageandwaitforresponse(self, message):
        transaction = self.newclienttransaction(message, self.proxy)
        transaction.wait()
        if not transaction.finalresponse:
            raise transaction.lastevent
        return transaction.finalresponse
    
    def options(self):
        log.info("%s querying for capabilities", self)
        options = Message.OPTIONS(
            self.domain,
            'From: {}'.format(self.addressofrecord),
            'To: {}'.format(self.addressofrecord),
            'Content-Type: application/sdp'
        )
        try:
            finalresponse = self.sendmessageandwaitforresponse(options)
        except Exception as e:
            log.info("%s querying failed: %s", self, e)
            return
        if finalresponse.familycode != 2:
            log.info("%s querying failed: %d %s", self, finalresponse.code, finalresponse.reason)
            return
        log.info("%s query ok", self)


class AuthenticationError(Exception):
    pass
class AuthenticationMixin:
    def mixininit(self, credentials=None, **kwargs):
        self.credentials = credentials
        return kwargs
    def sendmessageandwaitforresponse(self, message):
        transaction = self.newclienttransaction(message, self.proxy)
        transaction.wait()
        if transaction.finalresponse and transaction.finalresponse.code in (401, 407):
            if self.credentials is None:
                log.warning("no credential provided at initialization")
            else:
                log.info("%s %d retrying %s with authentication", self, transaction.finalresponse.code, message.METHOD)
                auth = message.authenticationheader(transaction.finalresponse, **self.credentials)
                if auth.header is None:
                    raise AuthenticationError(auth.error)
                message.addheaders(auth.header, replace=True)
                message.newbranch()
                transaction = self.newclienttransaction(message, self.proxy)
                transaction.wait()
        if not transaction.finalresponse:
            raise transaction.lastevent
        if transaction.finalresponse.code in (401, 407):
            raise AuthenticationError("{} {}".format(transaction.finalresponse.code, transaction.finalresponse.reason))
        return transaction.finalresponse


class RegistrationMixin:
    def mixininit(self, **kwargs):
        self.registered = False
        self.regtimer = None
        self.regcallid = None
        self.regseq = None
        return kwargs

    def register(self, expires=3600, async=False):
        if not async:
            return self._register(expires)
        threading.Thread(target=self._register, args=(expires,), daemon=True).start()

    def _register(self, expires=3600):
        Timer.unarm(self.regtimer)

        if expires > 0:
            log.info("%s %s for %ds", self, 're-registering' if self.registered else 'registering', expires)
        else:
            log.info("%s unregistering", self)

        register = Message.REGISTER(
            self.domain,
            'From: {}'.format(self.addressofrecord),
            'To: {}'.format(self.addressofrecord),
            'Contact: {}'.format(self.contacturi),
            'Expires: {}'.format(expires)
        )
        register.enforceheaders()
        if self.regcallid:
            register.callid = self.regcallid
            self.regseq += 1
            register.seq = self.regseq
        else:
            self.regcallid = register.callid
            self.regseq = register.seq
        try:
            finalresponse = self.sendmessageandwaitforresponse(register)
        except Exception as e:
            log.info("%s registering failed: %s", self, e)
            self.registered = False
            return self.registered
        if finalresponse.code == 423:
            minexpires = finalresponse.getheader('Min-Expires')
            log.info("%s registering failed: %s %s, %r", self, finalresponse.code, finalresponse.reason, minexpires)
            if minexpires:
                return self._register(minexpires.delta)
            else:
                return
        if finalresponse.familycode != 2:
            log.info("%s registering failed: %s %s", self, finalresponse.code, finalresponse.reason)
            return

        expiresheader = finalresponse.getheader('Expires')
        if expiresheader:
            gotexpires = expiresheader.delta
        contactheader = finalresponse.getheader('Contact')
        if contactheader:
            gotexpires = contactheader.params.get('expires')
        if gotexpires > 0:
            self.registered = True
            log.info("%s registered for %ds", self, gotexpires)
            Timer.arm(duration=gotexpires//2, cb=self.register, expires=expires, async=True)
        else:
            self.registered = False
            log.info("%s unregistered", self)
        return self.registered


class SessionMixin:
    def mixininit(self, mediaip=None, mediaport=None, pcapfilename=None, pcapfilter=None, **kwargs):
        self.session = None
        self.mediaip = mediaip or self.transport.localip
        self.mediaport = mediaport
        self.pcapfilename = pcapfilename
        self.pcapfilter = pcapfilter
        return kwargs

    def invite(self, touri, *headers):
        if self.session:
            raise Exception("session in progress")

        if isinstance(touri, SIPPhone):
            touri = touri.addressofrecord
        invite = Message.INVITE(touri, *headers)
        invite.addheaders(
            'From: {}'.format(self.addressofrecord),
            'Contact: {}'.format(self.contacturi),
            ifmissing=True
        )
        media = Media.Media(self.mediaip, self.mediaport, self.pcapfilename, self.pcapfilter)
        invite.setbody(*media.getlocaloffer())
        log.info("%s inviting %s with %s", self, touri, invite.getheader('Content-Type'))
        try:
            finalresponse = self.sendmessageandwaitforresponse(invite)
        except Exception as e:
            log.info("%s invitation failed: %s", self, e)
            return
        if finalresponse.familycode != 2:
            log.info("%s invitation failed: %s %s", self, finalresponse.code, finalresponse.reason)
            return
        log.info("%s invitation ok", self)
        session = Dialog.Session(self, invite, finalresponse, media)
        if not media.setremoteoffer(finalresponse.body):
            log.info("%s incompatible codecs -> bying", self)
            session.bye()
            return
        self.session = session
        return self.session

    def INVITE_handler(self, invite):
        ident = Dialog.UASid(invite)
        if not ident:
            # out of dialog invitation
            log.info("%s invited by %s", self, invite.getheader('f').address)
            if self.session:
                log.info("%s busy -> rejecting", self)
                return invite.response(481)
            media = Media.Media(self.mediaip, self.mediaport, self.pcapfilename, self.pcapfilter)
            if not media.setremoteoffer(invite.body):
                log.info("%s incompatible codecs -> rejecting", self)
                return invite.response(488)
            log.info("%s accept invitation", self)
            response = invite.response(200, 'Contact: {}'.format(self.contacturi))
            response.setbody(*media.getlocaloffer())
            self.session = Dialog.Session(self, response, invite, media)
            return response

        if not self.session or ident != self.session.ident:
            log.info("%s invalid invitation by %s", self, invite.getheader('f').address)
            return invite.response(481)

        return self.session.invitehandler(invite)

    def BYE_handler(self, bye):
        ident = Dialog.UASid(bye)
        if not self.session or ident != self.session.ident:
            return bye.response(481)

        resp = self.session.byehandler(bye)
        self.session = None
        return resp

class SIPPhone(SessionMixin, RegistrationMixin, AuthenticationMixin, UAbase):
    pass

    
if __name__ == '__main__':
    import snl
    snl.loggers['UA'].setLevel('INFO')

    idA = dict(
        transport='eno1:5555',
        proxy='194.2.137.40',
        domain='sip:osk.nokims.eu',
        addressofrecord='sip:+33900821220@osk.nokims.eu',
        credentials=dict(username='+33900821220@osk.nokims.eu', password='nsnims2008'),
        mediaport=3456,
    )
    phoneA = snl.SIPPhone(**idA)
    phoneA.register(200)
    phoneA.register(0)
