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
from . import Transport
from . import Utils


class UAbase(Transaction.TransactionManager):
    def __init__(self, transport, proxy, domain, addressofrecord, T1=None, T2=None, T4=None):
        if isinstance(transport, str):
            port = None
            if ':' in transport:
                transport,port = transport.split(':', 1)
            if '.' in transport:
                transport = dict(address=transport)
            else:
                transport = dict(interface=transport)
            if port is not None:
                transport['port'] = port
        super().__init__(transport, T1, T2, T4)
        try:
            if isinstance(proxy, str):
                if ':' in proxy:
                    prox = proxy.split(':', 1)
                    self.proxy = (prox[0], int(prox[1]))
                else:
                    self.proxy = (proxy, None)
            else:
                assert isinstance(proxy, (list,tuple))
                assert len(proxy) == 2
                self.proxy = tuple(proxy)
        except:
            log.logandraise(Exception('invalid proxy definition {!r}'.format(proxy)))
        self.domain = domain
        self.addressofrecord = addressofrecord
        self.contacturi = SIPBNF.URI(self.addressofrecord)
        self.contacturi.host = self.transport.localip
        self.contacturi.port = self.transport.localport

    def destroy(self):
        self.transport.stop()

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
            if result.provisional is None:
                return

    def send(self, message):
            self.transport.send(message, self.proxy)

    def options(self):
        log.info("%s querying for capabilities", self)
        options = Message.OPTIONS(
            self.domain,
            Header.From(self.addressofrecord),
            Header.To(self.addressofrecord),
            Header.Content_Type('application/sdp')
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

UAfeatures = Utils.ParameterDict() # ordered and case-insensitive keys
class Mixin(type):
    def __new__(cls, name, bases, namespace, **kwds):
        mixin = type.__new__(cls, name, bases, namespace)
        UAfeatures[name] = mixin
        return mixin

class Registration(metaclass=Mixin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.registered = False
        self.registermessage = None
        self.regtimer = None

    def register(self, expires=3600, *headers, async=False, reregister=0.5):
        if not isinstance(reregister, (int, float)):
            raise TypeError('expecting a number not {!r}'.format(reregister))
        if reregister<0 or reregister>1:
            raise ValueError('expecting a number in [0. - 1.]. got {}'.format(reregister))
        if not async:
            return self._register(expires, *headers, reregister=reregister)
        threading.Thread(target=self._register, args=(expires,*headers), kwargs=dict(reregister=reregister), daemon=True).start()

    def _register(self, expires, *headers, reregister):
        Timer.unarm(self.regtimer)

        if expires > 0:
            log.info("%s %s for %ds", self, 're-registering' if self.registermessage else 'registering', expires)
        else:
            log.info("%s unregistering", self)

        if self.registermessage is None:
            self.registermessage = Message.REGISTER(self.domain, *headers)
            self.registermessage.addheaders(
                Header.From(self.addressofrecord),
                Header.To(self.addressofrecord),
                Header.Contact(self.contacturi, params={'+g.3gpp.icsi-ref':"urn:urn-7:3gpp-service.ims.icsi.mmtel"}),
                ifmissing=True
            )
        else:
            self.registermessage.addheaders(*headers, replace=True)
            self.registermessage.seq += 1
        self.registermessage.addheaders(Header.Expires(delta=expires), replace=True)
        for result in self.sendmessage(self.registermessage):
            if result.success is not None:
                gotexpires = 0
                expiresheader = result.success.header('Expires')
                if expiresheader:
                    gotexpires = expiresheader.delta
                contactheader = result.success.header('Contact')
                if contactheader:
                    gotexpires = contactheader.params.get('expires')
                if gotexpires > 0:
                    self.registered = True
                    log.info("%s registered for %ds", self, gotexpires)
                    if reregister:
                        self.regtimer = Timer.arm(gotexpires*reregister, self.register, expires, async=True, reregister=reregister)
                else:
                    self.registered = False
                    self.registermessage = None
                    log.info("%s unregistered", self)
                return result.success

            elif result.error is not None:
                if result.error.code == 423:
                    minexpires = result.error.header('Min-Expires')
                    log.info("%s registering failed: %s %s, %r", self, result.error.code, result.error.reason, minexpires)
                    if minexpires:
                        return self.register(minexpires.delta, *headers)
                self.registermessage = None
                log.info("%s registering failed: %s %s", self, result.error.code, result.error.reason)
                return result.error

            elif result.provisional:
                pass

            elif result.exception:
                self.registermessage = None
                log.info("%s registering failed: %s", self, result.exception)
                return None


class Authentication(metaclass=Mixin):
    def __init__(self, credentials=None, **kwargs):
        super().__init__(**kwargs)
        self.credentials = credentials
        self.sa = None
        self.savedproxy = None
        self.saheaders = []

    def sendmessage(self, message):
        needsecurity = 'sec-agree' in self.extensions and message.METHOD == 'REGISTER'
        if needsecurity and self.sa is None:
            username = self.credentials.get('username')
            uri = self.credentials.get('uri', self.domain)
            realm = self.credentials.get('realm', username.partition('@')[2])
            self.saheaders.append(Header.Authorization(scheme='Digest', params=dict(username=username, uri=uri, realm=realm, nonce='', algorithm='AKAv1-MD5', response='')))
            self.sa = self.transport.prepareSA(self.proxy[0])
            for alg in Security.IPSEC_ALGS:
                for ealg in Security.IPSEC_EALGS:
                    self.saheaders.append(Header.Security_Client(mechanism='ipsec-3gpp', params=dict(**self.sa, alg=alg, ealg=ealg, prot='esp', mod='trans')))
        message.addheaders(*self.saheaders, replace=True)
        for result in super().sendmessage(message):
            if result.error is not None and result.error.code in (401, 407):
                if needsecurity:
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
                        if sec.mechanism=='ipsec-3gpp' and prot=='esp' and mod=='trans' and params['ealg'] in Security.IPSEC_EALGS and params['alg'] in Security.IPSEC_ALGS and q>bestq:
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
                    if needsecurity:
                        self.transport.establishSA(**securityserverparams, **auth.extra)
                        for sec in result.error.headers('security-server'):
                            verify = Header.Security_Verify(**dict(sec))
                            message.addheaders(verify)
                            self.saheaders.append(verify)
                        self.savedproxy = self.proxy
                        self.proxy = (self.proxy[0], securityserverparams['ports'])
                        self.contacturi.port = self.sa['ports']
                        message.contacturi.port = self.sa['ports']
                    message.addheaders(auth.header, replace=True)
                    message.seq = message.seq + 1
                    yield from super().sendmessage(message)
                    return
            else:
                yield result

    def _register(self, expires=3600, *headers, reregister):
        result = super()._register(expires, *headers, reregister=reregister)
        if expires==0 and result and self.sa:
            self.transport.terminateSA()
            self.sa = None
            if self.savedproxy:
                self.proxy = self.savedproxy
                self.savedproxy = None
            self.saheaders = []
            self.contacturi.port = self.transport.localport
        return result

class Session(metaclass=Mixin):
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
            Header.From(self.addressofrecord),
            Header.Contact(self.contacturi),
            ifmissing=True
        )
        media = self.mediaclass(ua=self, **self.mediaargs)
        invite.setbody(*media.getlocaloffer())
        log.info("%s inviting %s", self, touri)
        for result in self.sendmessage(invite):
            if result.success is not None:
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

            elif result.error is not None:
                log.info("%s invitation failed: %s %s", self, result.error.code, result.error.reason)
                return

            elif result.provisional is not None:
                pass

            elif result.exception is not None:
                log.info("%s invitation failed: %s", self, result.exception)
                return

    def askTU(self, invite):
        return invite.response(200, Header.Contact(self.contacturi))

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
                return invite.response(603)

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
                          Header.Call_ID(session.callid),
                          Header.From(session.localuri, params=dict(tag=session.localtag)),
                          Header.To(session.remoteuri, params=dict(tag=session.remotetag)),
                          Header.CSeq(seq=session.localseq, method='BYE'))
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


class Cancelation(metaclass=Mixin):
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


def SIPPhoneClass(features=UAfeatures.keys(), extensions=[]):
    if 'sec-agree' in extensions and not Security.SEC_AGREE:
        log.logandraise(Exception('sec-agree is not possible. try to run script as root'))
    ext = extensions

    if isinstance(features, str):
        features = features.replace(',', ' ').split()
    class cls(UAbase):
        extensions = ext
    for feature in features:
        if isinstance(feature, str):
            try:
                mixin = UAfeatures[feature]
            except:
                log.logandraise(Exception("unknown feature {}".format(feature)))
        else:
            mixin = feature
        class newcls(mixin, cls):
            pass
        cls = newcls
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
