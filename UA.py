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
        called = []
        for klass in reversed(self.__class__.mro()):
            init = getattr(klass, 'mixininit', None)
            if init and init not in called:
                kwargs = init(self, **kwargs)
                called.append(init)
        if kwargs:
            log.warning("got unexpected keyword argument {!r}".format(tuple(kwargs.keys())))

    def __str__(self):
        return str(self.contacturi)

    class Result:
        def __init__(self, event):
            self.success = self.provisional = self.error = self.exception = None
            if isinstance(event, Message.SIPResponse):
                if event.familycode == 2:
                    self.success = event
                elif event.familycode == 1:
                    self.provisional = event
                else:
                    self.error = event
            elif isinstance(event, Exception):
                self.exception = event

    def sendmessage(self, message):
        transaction = self.newclienttransaction(message, self.proxy)
        while True:
            event = transaction.wait()
            if event is None:
                return
            result = UAbase.Result(event)
            yield result
            if not result.provisional:
                return

    def options(self):
        log.info("%s querying for capabilities", self)
        options = Message.OPTIONS(
            self.domain,
            'From: {}'.format(self.addressofrecord),
            'To: {}'.format(self.addressofrecord),
            'Content-Type: application/sdp'
        )
        for result in self.sendmessage(options):
            if result.success:
                log.info("%s query ok", self)
            elif result.error:
                log.info("%s querying failed: %d %s", self, result.error.code, result.error.reason)
            elif result.provisional:
                pass
            elif result.exception:
                log.info("%s querying failed: %s", self, result.exception)


class CancelationMixin:
    def CANCEL_handler(self, cancel):
        transaction = self.transactionmatching(cancel, matchonbranch=True)
        if transaction:
            log.info("%s canceled by %s", self, cancel.getheader('f').address)
            resp = cancel.response(200)
            totag = transaction.eventcancel()
            if totag:
                resp.totag = totag
            return resp

        log.info("%s invalid cancelation from %s", self, cancel.getheader('f').address)
        return cancel.response(481)


class AuthenticationMixin:
    def mixininit(self, credentials=None, **kwargs):
        self.credentials = credentials
        return kwargs
    def sendmessage(self, message):
        for result in UAbase.sendmessage(self, message):
            if result.error and result.error.code in (401, 407):
                if self.credentials is None:
                    log.warning("%s no credential provided at initialization", self)
                    yield result
                else:
                    log.info("%s %d retrying %s with authentication", self, result.error.code, message.METHOD)
                    auth = message.authenticationheader(result.error, **self.credentials)
                    if auth.header is None:
                        yield UAbase.Result(Exception(auth.error))
                        return
                    message.addheaders(auth.header, replace=True)
                    message.newbranch()
                    message.seq = message.seq + 1
                    yield from UAbase.sendmessage(self, message)
                    return
            else:
                yield result


class RegistrationMixin:
    def mixininit(self, **kwargs):
        self.registermessage = None
        self.regtimer = None
        return kwargs

    def register(self, expires=3600, *headers, async=False):
        if not async:
            return self._register(expires, *headers)
        threading.Thread(target=self._register, args=(expires,*headers), daemon=True).start()

    def _register(self, expires=3600, *headers):
        Timer.unarm(self.regtimer)

        if expires > 0:
            log.info("%s %s for %ds", self, 're-registering' if self.register else 'registering', expires)
        else:
            log.info("%s unregistering", self)

        if self.registermessage is None:
            self.registermessage = Message.REGISTER(self.domain, *headers)
            self.registermessage.addheaders(
                'From: {}'.format(self.addressofrecord),
                'To: {}'.format(self.addressofrecord),
                'Contact: {}'.format(self.contacturi),
                'Expires: {}'.format(expires),
                ifmissing=True
            )
            self.registermessage.enforceheaders()
        else:
            self.registermessage.seq = self.registermessage.seq + 1
            self.registermessage.newbranch()
        self.registermessage.addheaders('Expires: {}'.format(expires), replace=True)
        for result in self.sendmessage(self.registermessage):
            if result.success:
                expiresheader = result.success.getheader('Expires')
                if expiresheader:
                    gotexpires = expiresheader.delta
                contactheader = result.success.getheader('Contact')
                if contactheader:
                    gotexpires = contactheader.params.get('expires')
                if gotexpires > 0:
                    log.info("%s registered for %ds", self, gotexpires)
                    self.regtimer = Timer.arm(gotexpires//2, self.register, expires, async=True)
                else:
                    self.registermessage = None
                    log.info("%s unregistered", self)
                return self.registermessage is not None

            elif result.error:
                if result.error.code == 423:
                    minexpires = result.error.getheader('Min-Expires')
                    log.info("%s registering failed: %s %s, %r", self, result.error.code, result.error.reason, minexpires)
                    if minexpires:
                        return self.register(minexpires.delta, *headers)
                self.registermessage = None
                log.info("%s registering failed: %s %s", self, result.error.code, result.error.reason)
                return False

            elif result.provisional:
                pass

            elif result.exception:
                self.registermessage = None
                log.info("%s registering failed: %s", self, result.exception)
                return False


class SessionMixin:
    def mixininit(self, mediaargs={}, **kwargs):
        self.mediaargs = mediaargs
        self.sessions = []
        self.lock = threading.Lock()
        return kwargs

    def addsession(self, dialog, media):
        with self.lock:
            self.sessions.append((dialog, media))
    def getsession(self, key, pop=False):
        with self.lock:
            for i,(dialog,media) in enumerate(self.sessions):
                if isinstance(key, str) and dialog.ident == key:
                    break
                if isinstance(key, Dialog.Dialog) and dialog == key:
                    break
                if isinstance(key, Media.Media) and media == key:
                    break
            else:
                raise KeyError("no such session {!r}".format(key))
            if pop:
                del self.sessions[i]
            return dialog,media
    def popsession(self, key):
        return self.getsession(key, pop=True)

    def invite(self, touri, *headers):
        if isinstance(touri, SIPPhone):
            touri = touri.addressofrecord
        invite = Message.INVITE(touri, *headers)
        invite.addheaders(
            'From: {}'.format(self.addressofrecord),
            'Contact: {}'.format(self.contacturi),
            ifmissing=True
        )
        media = Media.Media(self, **self.mediaargs)
        invite.setbody(*media.getlocaloffer())
        log.info("%s inviting %s", self, touri)
        for result in self.sendmessage(invite):
            if result.success:
                log.info("%s invitation ok", self)
                dialog = Dialog.Dialog(invite, result.success, uac=True)
                self.addsession(dialog, media)
                try:
                    if not media.setremoteoffer(result.success.body):
                        log.info("%s incompatible codecs -> bying", self)
                        self.bye(dialog)
                        return
                    return dialog
                except Exception as exc:
                    log.info("%s %s -> bying", self, exc)
                    self.bye(dialog)
                    return

            elif result.error:
                log.info("%s invitation failed: %s %s", self, result.error.code, result.error.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s invitation failed: %s", self, result.exception)
                return

    def INVITE_handler(self, invite):
        ident = Dialog.UASid(invite)
        if not ident:
            # out of dialog invitation
            log.info("%s invited by %s", self, invite.getheader('f').address)
            if len(self.sessions) > 3:
                log.info("%s busy -> rejecting", self)
                return invite.response(481)
            try:
                media = Media.Media(self, **self.mediaargs)
                if not media.setremoteoffer(invite.body):
                    log.info("%s incompatible codecs -> rejecting", self)
                    return invite.response(488)
            except Exception as exc:
                log.info("%s %s -> rejecting", self, exc)
                return invite.response(500)
            log.info("%s accept invitation", self)
            response = invite.response(200, 'Contact: {}'.format(self.contacturi))
            response.setbody(*media.getlocaloffer())
            dialog = Dialog.Dialog(invite, response, uas=True)
            self.addsession(dialog, media)
            return response

        try:
            dialog,media = self.getsession(ident)
        except:
            log.info("%s invalid invitation by %s", self, invite.getheader('f').address)
            return invite.response(481)

    def bye(self, key):
        try:
            dialog,media = self.popsession(key)
        except Exception as e:
            log.warning(e)
            return

        log.info("%s closing locally", self)
        dialog.localseq += 1
        bye = Message.BYE(dialog.remotetarget,
                         'call-id:{}'.format(dialog.callid),
                         'from:<{}>;tag={}'.format(dialog.localtarget, dialog.localtag),
                         'to:<{}>;tag={}'.format(dialog.remotetarget, dialog.remotetag),
                         'cseq: {} BYE'.format(dialog.localseq))
        media.stop()
        for result in self.sendmessage(bye):
            if result.success:
                log.info("%s closing ok", self)
                return

            elif result.error:
                log.info("%s closing failed: %s %s", self, result.error.code, result.error.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s closing failed: %s", self, result.exception)
                return

    def BYE_handler(self, bye):
        ident = Dialog.UASid(bye)
        try:
            dialog,media = self.popsession(ident)
        except:
            return bye.response(481)

        log.info("%s closed by remote", self)
        media.stop()
        return bye.response(200)

class SIPPhone(SessionMixin, RegistrationMixin, AuthenticationMixin, CancelationMixin, UAbase):
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
