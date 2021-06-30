#! /usr/bin/python3
# coding: utf-8

import random
import logging
import time
import threading
import weakref
import atexit
import ipaddress
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

try:
    import card.USIM as USIM
except Exception as e:
    log.warning("cannot import card (%s). SIM-AKA authentication is not possible", e)
    USIM = None

class UAbase(Transaction.TransactionManager):
    def __init__(self, ua={}, identity={}, transport={}, transaction={}):
        super().__init__(transport, **transaction)

        ua = dict(ua)
        proxy = ua.pop('proxy', None)
        try:
            if isinstance(proxy, str):
                if ':' in proxy:
                    prox = proxy.split(':', 1)
                    self.proxy = (prox[0], int(prox[1]))
                else:
                    self.proxy = (proxy, None)
            elif isinstance(proxy, (list,tuple)):
                assert len(proxy) == 2
                self.proxy = tuple(proxy)
            elif isinstance(proxy, ipaddress.IPv4Address):
                self.proxy = (proxy.exploded, None)
        except:
            log.logandraise(Exception('invalid proxy definition {!r}'.format(proxy)))
        if ua:
            raise ValueError('unexpected UA parameters {}'.format(ua))

        identity =dict(identity)
        self.identity = dict(usim=None)
        self.addressofrecord = self.domain = None
        iccid = identity.pop('iccid', None)
        if iccid:
            if not USIM:
                log.logandraise(Exception("card module not present"))
            try:
                usim = USIM.USIM()
                i = usim.get_ICCID()
                usim.disconnect()
                usim = USIM.USIM()
                imsi = usim.get_imsi()
            except Exception as e:
                log.logandraise(e)
            if i is None:
                log.logandraise(Exception('cannot read ICCID'))
            if iccid != 'any' and i != iccid:
                log.logandraise(Exception('bad ICCID expecting {} got {}'.format(iccid, i)))
            if imsi is None:
                log.logandraise(Exception('cannot read IMSI'))
            realm = identity.get('realm', 'ims.mnc{:03}.mcc{:03}.3gppnetwork.org'.format(int(imsi[3:5]), int(imsi[:3])))
            username = identity.get('username', '{}@{}'.format(imsi, realm))
            self.identity.update(iccid=iccid, usim=usim, imsi=imsi, realm=realm, username=username)
            log.debug("Reading USIM n° {}".format(iccid))
            log.debug("IMSI = {}".format(imsi))
            log.debug("realm = {}".format(realm))
            log.debug("username = {}".format(username))
            self.domain = 'sip:{}'.format(realm)
            self.addressofrecord = 'sip:{}'.format(username)

        self.addressofrecord = identity.pop('aor', self.addressofrecord)
        self.contacturi = SIPBNF.URI(self.addressofrecord) if self.addressofrecord else None
        self.domain = identity.pop('domain', self.domain or 'sip:{}'.format(self.contacturi.host) if self.contacturi else None)

        for key in ('realm', 'username', 'uri', 'K', 'OP', 'password'):
            self.identity[key] = identity.pop(key, self.identity.get(key))
        if not self.identity['uri']:
            self.identity['uri'] = self.domain
        if not self.identity['username']:
            self.identity['username'] = self.addressofrecord.split(':', 1)[1]
        if not self.identity['realm']:
            if self.identity['username']:
                self.identity['realm'] = self.identity['username'].partition('@')[2]
            elif self.domain:
                self.identity['realm'] = self.domain.split(':', 1)[1]
        if identity:
            raise ValueError('unexpected identity parameters {}'.format(identity))
        if self.contacturi:
            self.contacturi.host = self.transport.localip
            self.contacturi.port = self.transport.localport
#            self.contacturi.params['user'] = 'phone'

    def __str__(self):
        return str(self.contacturi)

    class Result:
        def __init__(self, event):
            self.success = self.provisional = self.error = self.exception = False
            if isinstance(event, Message.SIPResponse):
                if event.familycode == 2:
                    self.success = True
                elif event.familycode == 1:
                    self.provisional = True
                else:
                    self.error = True
            elif isinstance(event, Exception):
                self.exception = True

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
            yield result,event
            if not result.provisional:
                return

    def send(self, message):
            self.transport.send(message, self.proxy)

    def options(self, *headers, body=None):
        log.info("%s querying for capabilities", self)
        options = Message.OPTIONS(self.domain, *headers, body=body)
        options.addheaders(
            Header.From(self.addressofrecord),
            Header.To(self.addressofrecord),
            Header.Content_Type('application/sdp'),
            ifmissing=True
        )
        for result,event in self.sendmessage(options):
            if result.success:
                log.info("%s query ok", self)
                return event
            elif result.error:
                log.info("%s querying failed: %d %s", self, event.code, event.reason)
                return
            elif result.provisional:
                pass
            elif result.exception:
                log.info("%s querying failed: %s", self, event)
                return

    def OPTIONS_handler(self, options):
        response = options.response(200)
        if self.allow:
            response.addheaders(
                'Allow: {}'.format(', '.join(self.allow))
            )
        return response

tobeunregistered = weakref.WeakSet()
@atexit.register
def unregisterphones():
    global tobeunregistered
    for phone in tobeunregistered:
        if phone.registered:
            phone.register(0)

class RegistrationManager:
    def __init__(self, registration={}, **kwargs):
        registration = dict(registration)
        self.autoreg = registration.pop('autoreg', True)
        self.autounreg = registration.pop('autounreg', self.autoreg)
        self.reregister = registration.pop('reregister', 0.5)
        if not isinstance(self.reregister, (int, float)):
            raise TypeError('expecting a number for reregister not {!r}'.format(self.reregister))
        if self.reregister<0 or self.reregister>1:
            raise ValueError('expecting a number in [0. - 1.] for reregister. got {}'.format(self.reregister))
        self.expires = registration.pop('expires', 3600)
        if not isinstance(self.expires, (int, float)):
            raise TypeError('expecting a number for expires not {!r}'.format(self.expires))
        self.contactparams = registration.pop('contactparams', dict())
        if not isinstance(self.contactparams, dict):
            raise TypeError('expecting a dict for contactparams not {!r}'.format(self.contactparams))
        if registration:
            raise ValueError('unexpecting registration parameters {}'.format(registration))
        super().__init__(**kwargs)
        self.registered = False
        self.registermessage = None
        self.regtimer = None

        if self.autoreg and self.addressofrecord:
            self.register()

        global tobeunregistered
        if self.autounreg and self.addressofrecord:
            tobeunregistered.add(self)

    def register(self, expires=None, *headers, asynch=False):
        expires = expires if expires is not None else self.expires
        if not asynch:
            return self._register(expires, *headers)
        threading.Thread(target=self._register, args=(expires,*headers), daemon=True).start()

    def _register(self, expires, *headers):
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
                Header.Contact(self.contacturi, params=self.contactparams),
                ifmissing=True
            )
        else:
            self.registermessage.addheaders(*headers, replace=True)
            self.registermessage.seq += 1
        self.registermessage.addheaders(Header.Expires(delta=expires), replace=True)
        for result,event in self.sendmessage(self.registermessage):
            if result.success:
                gotexpires = 0
                expiresheader = event.header('Expires')
                if expiresheader:
                    gotexpires = expiresheader.delta
                contactheader = event.header('Contact')
                if contactheader:
                    gotexpires = contactheader.params.get('expires')
                if gotexpires > 0:
                    self.registered = True
                    log.info("%s registered for %ds", self, gotexpires)
                    if self.reregister:
                        self.regtimer = Timer.arm(gotexpires*self.reregister, self.register, expires, *headers, asynch=True)
                    if 'reg-event' in self.extensions:
                        self.subscribe('reg', expires=expires)
                    self.associateduris = [h.address for h in event.headers('P-Associated-URI')]
                    return True
                else:
                    self.registered = False
                    self.registermessage = None
                    log.info("%s unregistered", self)
                    return False

            elif result.error:
                if event.code == 423:
                    minexpires = event.header('Min-Expires')
                    log.info("%s registering failed: %s %s, %r", self, event.code, event.reason, minexpires)
                    if minexpires:
                        return self.register(minexpires.delta, *headers)
                self.registermessage = None
                log.info("%s registering failed: %s %s", self, event.code, event.reason)
                return False

            elif result.provisional:
                pass

            elif result.exception:
                self.registermessage = None
                log.info("%s registering failed: %s", self, event)
                return False


class AuthenticationManager:
    def __init__(self, **kwargs):
        self.sa = None
        self.savedproxy = None
        self.saheaders = []
        super().__init__(**kwargs)

    def sendmessage(self, message):
        needsecurity = 'sec-agree' in self.extensions and message.METHOD == 'REGISTER'
        if needsecurity and self.sa is None:
            username = self.identity.get('username')
            uri = self.identity.get('uri')
            realm = self.identity.get('realm')
            self.saheaders.append(Header.Authorization(scheme='Digest', params=dict(username=username, uri=uri, realm=realm, nonce='', algorithm='AKAv1-MD5', response='')))
            self.sa = self.transport.prepareSA(self.proxy[0])
#            val = []
            for alg in Security.IPSEC_ALGS:
                for ealg in Security.IPSEC_EALGS:
                    self.saheaders.append(Header.Security_Client(mechanism='ipsec-3gpp', params=dict(**self.sa, alg=alg, ealg=ealg, prot='esp', mod='trans')))
#                    h=Header.Security_Client(mechanism='ipsec-3gpp', params=dict(**self.sa, alg=alg, ealg=ealg, prot='esp', mod='trans'))
#                    val.append(str(h).split(':',1)[1].strip())
#            self.saheaders.append(Header.Header(name='Security-Client', value=','.join(val)))
        message.addheaders(*self.saheaders, replace=True)
        for result,event in super().sendmessage(message):
            if result.error and event.code in (401, 407):
                if needsecurity:
                    bestq = -1
                    for sec in event.headers('security-server'):
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
                        yield result,event
                log.info("%s %d retrying %s with authentication", self, event.code, message.METHOD)
                auth = message.authenticationheader(event, **self.identity)
                if auth.header is None:
                    error = Exception(auth.error)
                    yield UAbase.Result(error),error
                    return
                if needsecurity:
                    self.transport.establishSA(**securityserverparams, **auth.extra)
                    for sec in event.headers('security-server'):
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
                yield result,event

    def _register(self, expires=3600, *headers):
        registered = super()._register(expires, *headers)
        if expires==0 and self.sa:
            self.transport.terminateSA()
            self.sa = None
            if self.savedproxy:
                self.proxy = self.savedproxy
                self.savedproxy = None
            self.saheaders = []
            self.contacturi.port = self.transport.localport
        return registered

class SessionManager:
    def __init__(self, session={}, **kwargs):
        session = dict(session)
        self.mediaclass = session.pop('media', Media.Media)
        self.mediaargs = session.pop('mediaargs', {})
        if session:
            raise ValueError('unexpecting session parameters {}'.format(session))
        self.sessions = []
        self.lock = threading.Lock()
        super().__init__(**kwargs)

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

    def invite(self, touri, *headers, asynch=False):
        if isinstance(touri, UAbase):
            touri = touri.addressofrecord
        invite = Message.INVITE(touri, *headers)
        invite.addheaders(
            Header.From(self.addressofrecord),
            Header.Contact(self.contacturi),
            ifmissing=True
        )
        media = self.mediaclass(ua=self, **self.mediaargs)
        invite.media = media
        invite.setbody(*media.getlocaloffer())
        log.info("%s inviting %s", self, touri)
        if not asynch:
            return self._invite(invite)
        threading.Thread(target=self._invite, args=(invite,), daemon=True).start()
        return invite

    def _invite(self, invite):
        media = invite.media
        for result,event in self.sendmessage(invite):
            if result.success:
                log.info("%s invitation ok", self)
                session = Dialog.Session(invite, event, uac=True)
                self.addsession(session, media)
                try:
                    if not media.setremoteoffer(event.body):
                        log.info("%s incompatible codecs -> bying", self)
                        self.bye(session)
                        return
                    return session
                except Exception as exc:
                    log.info("%s %s -> bying", self, exc)
                    self.bye(session)
                    return

            elif result.error:
                log.info("%s invitation failed: %s %s", self, event.code, event.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s invitation failed: %s", self, event)
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
        for result,event in self.sendmessage(bye):
            if result.success:
                log.info("%s closing ok", self)
                return

            elif result.error:
                log.info("%s closing failed: %s %s", self, event.code, event.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s closing failed: %s", self, event)
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


class CancelationManager:
    def cancel(self, invite):
        log.info("%s canceling %s", self, invite.branch)
        for result,event in self.sendmessage(invite.cancel()):
            if result.success:
                log.info("%s cancel ok", self)
                return

            elif result.error:
                log.info("%s canceling failed: %s %s", self, event.code, event.reason)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s canceling failed: %s", self, event)
                return

    def CANCEL_handler(self, cancel):
        transaction = self.transactionmatching(cancel, matchonlyonbranch=True)
        if transaction:
            log.info("%s canceled by %s", self, cancel.fromaddr)
            resp = cancel.response(200)
            totag = transaction.eventcancel()
            if totag:
                resp.totag = totag
            return resp

        log.info("%s invalid cancelation from %s", self, cancel.fromaddr)
        return cancel.response(481)

class NotificationManager:
    class Subscription:
        def __init__(self):
            self.subscribe = None

    # todo:
    #  -dialog management
    #  -timerN and subscription state management

    def __init__(self, **kwargs):
        self.subscriptions = {}
        super().__init__(**kwargs)

    def subscribe(self, event, expires, *headers):
        if event not in self.subscriptions:
            self.subscriptions[event] = NotificationManager.Subscription()
        subscription = self.subscriptions[event]

        if subscription.subscribe is None:
            subscription.subscribe = Message.SUBSCRIBE(self.addressofrecord, *headers)
            subscription.subscribe.addheaders(
                Header.From(self.addressofrecord),
                Header.To(self.addressofrecord),
                Header.Contact(self.contacturi),
                Header.Event(event),
                ifmissing=True
            )
        else:
            subscription.subscribe.addheaders(*headers, replace=True)
            subscription.subscribe.seq += 1
        subscription.subscribe.addheaders(Header.Expires(delta=expires), replace=True)

        log.info("%s subscribing to %r", self, event)
        for result,event in self.sendmessage(subscription.subscribe):
            if result.success:
                log.info("%s subscription ok", self)
                return

            elif result.error:
                log.info("%s subscription failed: %s %s", self, event.code, event.reason)
                self.subscription.remove(event)
                return

            elif result.provisional:
                pass

            elif result.exception:
                log.info("%s subscription failed: %s", self, event)
                self.subscription.remove(event)
                return

    def NOTIFY_handler(self, notify):
        return notify.response(200)

classcache = {}
def SIPPhoneClass(*extensions):
    for extension in set(extensions):
        if extension == 'sec-agree':
            Security.initsecagree()
        elif extension == 'reg-event':
            pass
        else:
            log.logandraise(Exception('unknown extension {}'.format(extension)))
    ext = frozenset(extensions)

    if ext not in classcache:
        class SIPPhone(NotificationManager, CancelationManager, SessionManager, AuthenticationManager, RegistrationManager, UAbase):
            extensions = ext
        classcache[ext] = SIPPhone
    return classcache[ext]

if __name__ == '__main__':
    import snl
    snl.loggers['UA'].setLevel('INFO')

    config = dict(
        transport='eno1:5555',
        proxy='194.2.137.40',
        domain='sip:osk.nokims.eu',
        addressofrecord='sip:+33900821220@osk.nokims.eu',
        registration=dict(autoregister=True, expires=200, reregister=0.5, autounregister=True),
        credentials=dict(username='+33900821220@osk.nokims.eu', password='nsnims2008'),
        mediaargs=dict(port=3456),
    )
    phone = snl.SIPPhoneClass()(**config)
