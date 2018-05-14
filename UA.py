#! /usr/bin/python3
# coding: utf-8

import random
import logging
import time
import threading
log = logging.getLogger('UA')

from . import SIPBNF
from . import Message
from . import Header
from . import Transaction
from . import Media
from . import Timer
from . import Dialog
from . import Security

class UAbase(Transaction.TransactionManager):
    @classmethod
    def addmixin(cls, *mixins):
        for mixin in mixins:
            class newcls(mixin, cls):
                pass
            cls = newcls
        return cls

    def __init__(self, transport, proxy, domain, addressofrecord, T1=None, T2=None, T4=None):
        super().__init__(transport, T1, T2, T4)
        self.proxy = proxy
        self.domain = domain
        self.addressofrecord = addressofrecord
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = self.transport.localip
        self.contacturi.port = self.transport.localport

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
        if 'sec-agree' in self.extensions:
            if message.METHOD != 'ACK':
                message.addheaders('Supported: sec-agree', replace=True)
            if message.METHOD == 'REGISTER':
                message.addheaders('Require: sec-agree', replace=True)
                message.addheaders('Proxy-Require: sec-agree', replace=True)

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
            log.info("%s canceled by %s", self, cancel.fromaddr)
            resp = cancel.response(200)
            totag = transaction.eventcancel()
            if totag:
                resp.totag = totag
            return resp

        log.info("%s invalid cancelation from %s", self, cancel.fromaddr)
        return cancel.response(481)


class AuthenticationMixin:
    def __init__(self, credentials=None, **kwargs):
        super().__init__(**kwargs)
        self.credentials = credentials
    def sendmessage(self, message):
        security = 'sec-agree' in self.extensions and message.METHOD == 'REGISTER'
        if security:
            username = self.credentials.get('username')
            uri = self.credentials.get('uri', self.domain)
            realm = self.credentials.get('realm', username.partition('@')[2])
            message.addheaders(Header.Authorization(scheme='Digest', params=dict(username=username, uri=uri, realm=realm, nonce='', algorithm='AKAv1-MD5', response='')))
            sa = self.transport.prepareSA(self.proxy)
            ALGS = ('hmac-md5-96',)#'hmac-sha-1-96')
            EALGS = ('des-ede3-cbc','aes-cbc','null')
            for alg in ALGS:
                for ealg in EALGS:
                    message.addheaders(Header.Security_Client(mechanism='ipsec-3gpp', params=dict(**sa, alg=alg, ealg=ealg, prot='esp', mod='trans')))
        for result in super().sendmessage(message):
            if result.error and result.error.code in (401, 407):
                if security:
                    bestq = -1
                    for sec in result.error.headers('security-server'):
                        q = sec.params.get('q',0.)
                        prot = sec.params.get('prot','esp')
                        mod = sec.params.get('mod','trans')
                        try:
                            params = {k:sec.params[k] for k in ('spic', 'spis', 'portc', 'ports', 'alg')}
                        except:
                            continue # missing mandatory parameter
                        params['ealg'] = sec.params.get('ealg', 'null')
                        if sec.mechanism=='ipsec-3gpp' and prot=='esp' and mod=='trans' and params['ealg'] in EALGS and params['alg'] in ALGS and q>bestq:
                            bestq = q
                            securityserverparams = params
                    if bestq == -1:
                        log.warning("%s no matching algorithm found for SA", self)
                        yield result
                if self.credentials is None:
                    log.warning("%s no credential provided at initialization", self)
                    yield result
                else:
                    log.info("%s %d retrying %s with authentication", self, result.error.code, message.METHOD)
                    auth = message.authenticationheader(result.error, **self.credentials)
                    if auth.header is None:
                        yield UAbase.Result(Exception(auth.error))
                        return
                    if security:
                        self.transport.establishSA(**securityserverparams, **auth.extra)
                        for sec in result.error.headers('security-server'):
                            message.addheaders(Header.Security_Verify(**dict(sec)))
                    message.addheaders(auth.header, replace=True)
                    message.newbranch()
                    message.seq = message.seq + 1
                    yield from super().sendmessage(message)
                    return
            else:
                yield result


class RegistrationMixin:
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.registermessage = None
        self.regtimer = None

    def register(self, expires=3600, *headers, async=False):
        if not async:
            return self._register(expires, *headers)
        threading.Thread(target=self._register, args=(expires,*headers), daemon=True).start()

    def _register(self, expires=3600, *headers):
        Timer.unarm(self.regtimer)

        if expires > 0:
            log.info("%s %s for %ds", self, 're-registering' if self.registermessage else 'registering', expires)
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
                expiresheader = result.success.header('Expires')
                if expiresheader:
                    gotexpires = expiresheader.delta
                contactheader = result.success.header('Contact')
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
                    minexpires = result.error.header('Min-Expires')
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
    def __init__(self, mediaclass=Media.Media, mediaargs={}, **kwargs):
        super().__init__(**kwargs)
        self.mediaclass = mediaclass
        self.mediaargs = mediaargs
        self.sessions = []
        self.lock = threading.Lock()

    def addsession(self, session, media):
        with self.lock:
            self.sessions.append((session, media))
    def getsession(self, key, pop=False):
        with self.lock:
            for i,(session,media) in enumerate(self.sessions):
                if isinstance(key, str) and session.ident == key:
                    break
                if isinstance(key, Dialog.Session) and session == key:
                    break
                if isinstance(key, Media.Media) and media == key:
                    break
            else:
                raise KeyError("no such session {!r}".format(key))
            if pop:
                del self.sessions[i]
            return session,media
    def popsession(self, key):
        return self.getsession(key, pop=True)

    def invite(self, touri, *headers):
        if isinstance(touri, UAbase):
            touri = touri.addressofrecord
        invite = Message.INVITE(touri, *headers)
        invite.addheaders(
            'From: {}'.format(self.addressofrecord),
            'Contact: {}'.format(self.contacturi),
            ifmissing=True
        )
        media = self.mediaclass(ua=self, **self.mediaargs)
        invite.setbody(*media.getlocaloffer())
        log.info("%s inviting %s", self, touri)
        for result in self.sendmessage(invite):
            if result.success:
                log.info("%s invitation ok", self)
                session = Dialog.Session(invite, result.success, uac=True)
                self.addsession(session, media)
                try:
                    if not media.setremoteoffer(result.success.body):
                        log.info("%s incompatible codecs -> bying", self)
                        self.bye(session)
                        return
                    return session
                except Exception as exc:
                    log.info("%s %s -> bying", self, exc)
                    self.bye(session)
                    return

            elif result.error:
                log.info("%s invitation failed: %s %s", self, result.error.code, result.error.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s invitation failed: %s", self, result.exception)
                return

    def askTU(self, invite):
        return invite.response(200, 'Contact: {}'.format(self.contacturi))

    def INVITE_handler(self, invite):
        ident = Dialog.UASid(invite)
        if not ident:
            # out of dialog invitation
            log.info("%s invited by %s", self, invite.fromaddr)

            response = self.askTU(invite)
            if response.familycode != 2:
                log.info("%s deny invitation", self)
                return response

            try:
                media = self.mediaclass(ua=self, **self.mediaargs)
                if not media.setremoteoffer(invite.body):
                    log.info("%s incompatible codecs -> rejecting", self)
                    return invite.response(488)
            except Exception as exc:
                log.info("%s %s -> rejecting", self, exc)
                return invite.response(500)

            log.info("%s accept invitation", self)
            response.setbody(*media.getlocaloffer())
            session = Dialog.Session(invite, response, uas=True)
            self.addsession(session, media)
            return response

        try:
            session,media = self.getsession(ident)
        except:
            log.info("%s invalid invitation by %s", self, invite.fromaddr)
            return invite.response(481)

    def bye(self, key):
        try:
            session,media = self.popsession(key)
        except Exception as e:
            log.warning(e)
            return

        log.info("%s closing locally", self)
        session.localseq += 1
        bye = Message.BYE(session.remotetarget,
                         'call-id:{}'.format(session.callid),
                         'from:<{}>;tag={}'.format(session.localuri, session.localtag),
                         'to:<{}>;tag={}'.format(session.remoteuri, session.remotetag),
                         'cseq: {} BYE'.format(session.localseq))
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
            session,media = self.popsession(ident)
        except:
            log.info("%s bying unknown session from %s", self, bye.fromaddr)
            return bye.response(481)

        log.info("%s closed by remote", self)
        media.stop()
        return bye.response(200)



def SIPPhoneClass(*extensions):
    if 'sec-agree' in extensions and not Security.SEC_AGREE:
        raise Exception('sec-agree is not possible. try to run script as root')
    cls = UAbase
    cls.extensions = extensions
    cls = cls.addmixin(CancelationMixin, AuthenticationMixin, RegistrationMixin, SessionMixin)
    return cls
    
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
