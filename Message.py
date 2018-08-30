# coding: utf-8

import re
import random
import string
import collections
import logging
log = logging.getLogger('Message')

from . import SIPBNF
from . import Header
from . import Tags
from . import Security

CRLF = b'\r\n'
STATUS_LINE_RE = re.compile(b'SIP/2.0 (?P<code>[1-7]\d\d) (?P<reason>.+)\r\n', re.IGNORECASE)
REQUEST_LINE_RE = re.compile(b'''(?P<method>[A-Za-z0-9.!%*_+`'~-]+) (?P<requesturi>[^ ]+) SIP/2.0\r\n''', re.IGNORECASE)
CONTENT_LENGTH_RE = re.compile(b'\r\n(?:Content-length|l)[ \t]*:\s*(?P<length>\d+)\s*\r\n', re.IGNORECASE)
UNFOLDING_RE = re.compile(b'[ \t]*\r\n[ \t]+')
class DecodeInfo:
    def __init__(self, buf):
        self.buf = buf
        self.status = None
        self.klass = None; self.startline = None;
        self.istart = None; self.iheaders = None; self.iblank = None; self.ibody = None; self.iend = None
        self.framing = False
        self.error = None

    def __str__(self):
        if self.istart is not None and self.iend is not None:
            displaybuf = bytes(self.buf[self.istart:self.istart+12] + b'...' +  self.buf[self.iend-12:self.iend])
        else:
            displaybuf = b''
        return "decodeinfo: status={0.status} error={0.error} class={0.klass} start={0.istart} headers={0.iheaders} blank={0.iblank} body={0.ibody} end={0.iend} {1}".format(self, displaybuf)

    def finish(self):
        rawheaders=self.buf[self.iheaders:self.iblank]
        body=self.buf[self.ibody:self.iend]
        if isinstance(self.buf, bytearray):
            del self.buf[:self.iend]
        headers = Header.Headers(rawheaders, strictparsing=False)
        if self.klass == SIPResponse:
            return SIPResponse(self.code, *headers.list(), reason=self.reason, body=body)
        elif self.klass == SIPRequest:
            return SIPRequest(self.requesturi, *headers.list(), body=body, method=self.method)
        else:
            return self.klass(self.requesturi, *headers.list(), body=body, method=self.method)

class SIPMessage(object):
    @staticmethod
    def frombytes(buf):
        decodeinfo = SIPMessage.predecode(buf)
        if decodeinfo.status == 'OK':
            return decodeinfo.finish()
        return None
    
    @staticmethod
    def predecode(buf):
        log.debug("predecode(%r)", buf)
        decodeinfo = DecodeInfo(buf)

        # Ignore leading CRLF
        offset = 0
        while buf[offset:].startswith(CRLF):
            offset += 2

        if offset == len(buf):
            decodeinfo.status = 'EMPTY'
            log.debug(decodeinfo)
            return decodeinfo

        # Is there at least one line?
        if CRLF not in buf[offset:]:
            decodeinfo.status = 'TRUNCATED'
            log.debug(decodeinfo)
            return decodeinfo

        # Valid messages:
        #  -valid status line + CRLF
        #  -optionals header, each ending with CRLF
        #  -a blank line (CRLF)
        #  -optional body
        
        # Decoding start-line
        statusline = STATUS_LINE_RE.match(buf, offset)
        requestline = REQUEST_LINE_RE.match(buf, offset)
        if not statusline and not requestline:
            decodeinfo.error = "Not a SIP message"
            decodeinfo.status = 'ERROR'
            log.debug(decodeinfo)
            return decodeinfo
        s_start = statusline.start() if statusline else len(buf)
        r_start = requestline.start() if requestline else len(buf)
        if s_start < r_start:
            try:
                reason = statusline.group('reason')
                decodeinfo.reason = reason.decode('utf-8')
            except UnicodeError as err:
                decodeinfo.error = "UTF-8 encoding error ({} {!r}) in Reason-Phrase: {!r}".format(err.reason, err.object[err.start:err.end], reason)
                decodeinfo.status = 'ERROR'
                log.debug(decodeinfo)
                return decodeinfo
            decodeinfo.istart = s_start
            decodeinfo.iheaders =  statusline.end()
            decodeinfo.klass = SIPResponse
            decodeinfo.code = int(statusline.group('code'))
        else:
            try:
                requesturi = requestline.group('requesturi')
                requesturi = requesturi.decode('ascii')
            except:
                decodeinfo.error = "ASCII encoding error in Request-URI: {!r}".format(requesturi)
                decodeinfo.status = 'ERROR'
                log.debug(decodeinfo)
                return decodeinfo
            decodeinfo.requesturi = requesturi
            decodeinfo.istart = r_start
            decodeinfo.iheaders =  requestline.end()
            decodeinfo.method = requestline.group('method').decode('ascii')
            decodeinfo.klass = SIPRequest.SIPrequestclasses.get(decodeinfo.method.upper(), SIPRequest)
        
        # Separating Headers from Body
        endofheaders = buf.find(CRLF+CRLF, decodeinfo.istart)
        if endofheaders != -1:
            decodeinfo.status = 'OK'
            decodeinfo.iblank = endofheaders+2
            decodeinfo.ibody = decodeinfo.iblank+2
            decodeinfo.iend = len(buf)

            # Finding Content-Length
            m = CONTENT_LENGTH_RE.search(buf, pos=decodeinfo.iheaders-2, endpos=decodeinfo.iblank)
            if m:
                contentheader = m.group(0).strip()
                contentheader = UNFOLDING_RE.sub(b' ', contentheader)
                if not b'\r' in contentheader and not b'\n' in contentheader:
                    contentlength = int(m.group('length'))
                    decodeinfo.framing = True
                    if contentlength > decodeinfo.iend - decodeinfo.ibody:
                        decodeinfo.status = 'TRUNCATED'
                    else:
                       decodeinfo.iend =  decodeinfo.ibody + contentlength

        log.debug(decodeinfo)
        return decodeinfo
    
    def __init__(self, *headers, body):
        self.setbody(body)
        self._headers = Header.Headers(*headers)
        self.fd = -1

    def setbody(self, body, contenttype=None):
        if body is None:
            self.body = b''
        elif isinstance(body, str):
            self.body = body.encode('utf8')
        elif isinstance(body, (bytes,bytearray)):
            self.body = bytes(body)
        else:
            raise TypeError("body should be of type str or bytes")
        if contenttype:
            self.addheaders('c:{}'.format(contenttype))

    def addheaders(self, *headers, replace=False, ifmissing=False):
        if replace and ifmissing:
            raise Exception("can't add headers with both replace=True and ifmissing=True")
        if replace:
            self._headers.replaceoradd(*headers)
        elif ifmissing:
            self._headers.addifmissing(*headers)
        else:
            self._headers.add(*headers)

    def headers(self, *names):
        return self._headers.list(*names)

    def removeheaders(self, *names):
        for name in names:
            while True:
                if self.popheader(name) is None:
                    break

    def header(self, name):
        return self._headers.first(name)

    def popheader(self, name):
        return self._headers.pop(name)

    def _getlength(self):
        cl = self.header('Content-Length')
        if cl:
            return cl.length
    def _setlength(self, length):
        cl = self.header('Content-Length')
        if cl:
            cl.length = length
        else:
            self.addheaders(Header.Content_Length(length=length))
    length = property(_getlength, _setlength)

    def _getbranch(self):
        via = self.header('Via')
        if via:
            return via.params.get('branch')
    def _setbranch(self, branch):
        via = self.header('Via')
        if not via:
            raise Exception("missing Via header")
        via.params['branch'] = branch
    branch = property(_getbranch, _setbranch)

    def _getfromtag(self):
        f = self.header('From')
        if f:
            return f.params.get('tag')
    def _setfromtag(self, tag):
        f = self.header('From')
        if not f:
            raise Exception("missing From header")
        f.params['tag'] = tag
    fromtag = property(_getfromtag, _setfromtag)

    def _getfromaddr(self):
        f = self.header('From')
        if f:
            return f.address
    def _setfromaddr(self, addr):
        f = self.header('From')
        if f:
            f.address = addr
        else:
            self.addheaders(Header.From(display=None, address=addr, params=None))
    fromaddr = property(_getfromaddr, _setfromaddr)

    def _gettotag(self):
        t = self.header('To')
        if t:
            return t.params.get('tag')
    def _settotag(self, tag):
        t = self.header('To')
        if not t:
            raise Exception("missing To header")
        t.params['tag'] = tag
    totag = property(_gettotag, _settotag)

    def _gettoaddr(self):
        t = self.header('To')
        if t:
            return t.address
    def _settoaddr(self, addr):
        t = self.header('To')
        if t:
            t.address = addr
        else:
            self.addheaders(Header.To(display=None, address=addr, params=None))
    toaddr = property(_gettoaddr, _settoaddr)

    def _getcontacturi(self):
        c = self.header('Contact')
        if c:
            return c.address
    def _setcontacturi(self, uri):
        c = self.header('Contact')
        if c:
            c.address = uri
        else:
            self.addheaders(Header.Contact(display=None, address=uri, params=None))
    contacturi = property(_getcontacturi, _setcontacturi)

    def _getcallid(self):
        c = self.header('Call-Id')
        if c:
#            if hasattr(c, 'callid'):
                return c.callid
#            else:
#                return c.value
    def _setcallid(self, cid):
        c = self.header('Call-Id')
        if c:
            c.callid = cid
        else:
            self.addheaders(Header.Call_ID(callid=cid))
    callid = property(_getcallid, _setcallid)

    def _getseq(self):
        c = self.header('CSeq')
        if c:
            return c.seq
    def _setseq(self, seq):
        c = self.header('CSeq')
        if c:
            c.seq = seq
        else:
           self.addheaders(Header.Cseq(seq=seq, method=self.METHOD))
    seq = property(_getseq, _setseq)

    @property
    def CseqMETHOD(self):
        c = self.header('CSeq')
        if c:
            return c.method.upper()

    def tolines(self, headerform='nominal'):
        ret = [self.startline()]
        for header in self.headers():
            ret.append(header.tobytes(headerform))
        ret.append(b'')
        return ret

    def tobytes(self, headerform='nominal'):
        return b'\r\n'.join(self.tolines(headerform) + [self.body])

    def __bytes__(self):
        return self.tobytes()

    def __str__(self):
        try:
            str = self.tobytes().decode('utf-8')
            if not '\x00' in str:
                return str
        except:
            pass
        return '\r\n'.join((repr(line)[2:-1] for line in self.tolines() + self.body.split(b'\r\n')))

class SIPResponse(SIPMessage):
    defaultreasons = {100:'Trying', 180:'Ringing', 181:'Call is Being Forwarded', 182:'Queued', 183:'Session in Progress', 199:'Early Dialog Terminated', 200:'OK', 202:'Accepted', 204:'No Notification', 300:'Multiple Choices', 301:'Moved Permanently', 302:'Moved Temporarily', 305:'Use Proxy', 380:'Alternative Service', 400:'Bad Request', 401:'Unauthorized', 402:'Payment Required', 403:'Forbidden', 404:'Not Found', 405:'Method Not Allowed', 406:'Not Acceptable', 407:'Proxy Authentication Required', 408:'Request Timeout', 409:'Conflict', 410:'Gone', 411:'Length Required', 412:'Conditional Request Failed', 413:'Request Entity Too Large', 414:'Request-URI Too Long', 415:'Unsupported Media Type', 416:'Unsupported URI Scheme', 417:'Unknown Resource-Priority', 420:'Bad Extension', 421:'Extension Required', 422:'Session Interval Too Small', 423:'Interval Too Brief', 424:'Bad Location Information', 428:'Use Identity Header', 429:'Provide Referrer Identity', 430:'Flow Failed', 433:'Anonymity Disallowed', 436:'Bad Identity-Info', 437:'Unsupported Certificate', 438:'Invalid Identity Header', 439:'First Hop Lacks Outbound Support', 470:'Consent Needed', 480:'Temporarily Unavailable', 481:'Call/Transaction Does Not Exist', 482:'Loop Detected.', 483:'Too Many Hops', 484:'Address Incomplete', 485:'Ambiguous', 486:'Busy Here', 487:'Request Terminated', 488:'Not Acceptable Here', 489:'Bad Event', 491:'Request Pending', 493:'Undecipherable', 494:'Security Agreement Required', 500:'Server Internal Error', 501:'Not Implemented', 502:'Bad Gateway', 503:'Service Unavailable', 504:'Server Time-out', 505:'Version Not Supported', 513:'Message Too Large', 580:'Precondition Failure', 600:'Busy Everywhere', 603:'Decline', 604:'Does Not Exist Anywhere', 606:'Not Acceptable'}
    def __init__(self, code, *headers, body=None, reason=None, **kw):
        self.code = code
        self.familycode = code // 100
        self.reason = reason if reason is not None else self.defaultreasons.get(code, '')
        log.debug("New response: code={} reason={}".format(self.code, self.reason))
        SIPMessage.__init__(self, *headers, body=body)

    def startline(self):
        return 'SIP/2.0 {} {}'.format(self.code, self.reason).encode('utf-8')

    def __bool__(self):
        return self.familycode == 2

class RequestMeta(type):
    @staticmethod
    def __prepare__(name, bases, **dikt):
        return dict(method=name, METHOD=name.upper())
    def __init__(cls, name, bases, dikt):
        if name != 'SIPRequest':
            SIPRequest.SIPrequestclasses[name] = cls
        super(RequestMeta, cls).__init__(name, bases, dikt)
        
class SIPRequest(SIPMessage, metaclass=RequestMeta):
    SIPrequestclasses = {}
    def __init__(self, uri, *headers, body=None, method=None, **kw):
        log.debug("New request: method={} uri={}".format(method, uri))
        SIPMessage.__init__(self, *headers, body=body)
        self.uri = uri if isinstance(uri, SIPBNF.URI) else SIPBNF.URI(uri)
        if method is not None:
            self.method = method
            self.METHOD = method.upper()
        self.responsetotag = None

    def enforceheaders(self):
        self.addheaders(
            Header.Via(
                protocol='???',
                host='0.0.0.0',
                port=None,
                params={}
            ),
            Header.From(display=None, address=self.uri, params={}),
            Header.To(display=None, address=self.uri, params={}),
            Header.Max_Forwards(max=70),
            Header.CSeq(seq=random.randint(0,0x7fff), method=self.METHOD),
            ifmissing=True
        )
        self.branch = Tags.branch()
        try:
            if self.callid is None:
                self.callid = Tags.callid()
        except:
            pass
        try:
            if self.fromtag is None:
                self.fromtag = Tags.fromto()
        except:
            pass

    def startline(self):
        return '{} {} SIP/2.0'.format(self.method, self.uri).encode('utf-8')

    def authenticationheader(self, response, nc=1, cnonce=None, **kwargs):
        Auth = collections.namedtuple('Auth', 'header extra error')
        Auth.__new__.__defaults__ = ({}, None)
        authenticates = response.headers('WWW-Authenticate', 'Proxy-Authenticate')
        if not authenticates:
            return Auth(header=None, error="missing WWW|Proxy-Authenticate header in response")

        for authenticate in authenticates:
            extra = {}
            log.info("Computing authentication with %s", authenticate)
            if authenticate.scheme.lower() != 'digest':
                log.warning("unknown authentication sheme %s", authenticate.scheme)
                continue
            algorithm = authenticate.params.get('algorithm', 'MD5')
            if algorithm.lower() not in ('md5', 'md5-sess', 'akav1-md5'):
                log.warning("unknown algorithm %s", algorithm)
                continue

            if algorithm.lower() == 'akav1-md5':
                K = kwargs.pop('K', None)
                if K is None:
                    log.warning("missing K in credentials. Using 0")
                    K = 16*b'\x00'
                if len(K) < 16:
                    log.warning("K too short. Padding with 0")
                    K = K + (16-len(K))*b'\x00'
                if len(K) > 16:
                    log.warning("K too long. Keeping MSB")
                    K = K[:16]
                OP = kwargs.pop('OP', None)
                if OP is None:
                    log.warning("missing OP in credentials. Using 0")
                    OP = 16*b'\x00'
                if len(OP) < 16:
                    log.warning("OP too short. Padding with 0")
                    OP = OP + (16-len(OP))*b'\x00'
                if len(OP) > 16:
                    log.warning("OP too long. Keeping MSB")
                    OP = OP[:16]
                try:
                    res,ik,ck = Security.AKA(authenticate.params.get('nonce'), K, OP)
                except Exception as e:
                    log.warning(str(e) + ". Cannot satisfy AKAv1 authentication")
                    continue
                kwargs['password'] = res
                extra = dict(ik=ik, ck=ck)

            username = kwargs.pop('username', None)
            if username is None:
                log.warning("missing 'username' argument needed by Digest authentication")
                continue
            password = kwargs.pop('password', None)
            if password is None:
                log.warning("missing 'password' argument needed by Digest authentication")
                continue
            params = Security.digest(
                request=self,
                realm=authenticate.params.get('realm'),
                nonce=authenticate.params.get('nonce'),
                algorithm=algorithm,
                qop=authenticate.params.get('qop'),
                nc=nc,
                cnonce=cnonce or ''.join((random.choice(string.ascii_letters) for _ in range(20))),
                username=username,
                password=password)
            if authenticate._name == 'WWW-Authenticate':
                auth=Header.Authorization(scheme=authenticate.scheme, params=params)
            else:
                auth=Header.Proxy_Authorization(scheme=authenticate.scheme, params=params)
            return Auth(header=auth, extra=extra)
        return Auth(header=None, error="impossible to authenticate with received headers")

    def response(self, code, *headers, body=None, reason=None, **kw):
        resp = SIPResponse(code,
                           *self.headers('via', 'from', 'to', 'call-id', 'cseq'),
                           *headers,
                           body=body,
                           reason=reason,
                           **kw)
        resp.fd = self.fd
        if code != 100 and resp.totag is None:
            if self.responsetotag is None:
                self.responsetotag = Tags.fromto()
            resp.totag = self.responsetotag
        return resp
    
class REGISTER(SIPRequest):
    pass
class INVITE(SIPRequest):
    def ack(self, response):
        if response.familycode == 1:
            raise ValueError("cannot build an ACK from a 1xx response")
        uri = response.contacturi if response.familycode == 2 else self.uri
        ack = ACK(uri, *self.headers('from', 'cseq', 'call-id', 'via'), response.header('to'))
        ack.header('CSeq').method = 'ACK'
        return ack

class ACK(SIPRequest):
    pass
class OPTIONS(SIPRequest):
    pass
class CANCEL(SIPRequest):
    pass
class BYE(SIPRequest):
    pass

if __name__ == '__main__':
    import base64
    import binascii
    import snl
    snl.loggers['Message'].setLevel('INFO')

# ----------------------------------
    register = REGISTER('sip:osk.nokims.eu')
    params = register.digest(realm="osk.nokims.eu",
                           nonce="7800e38558e368911AQ8918b7eeaf71a794f910eafbdb376e8848d",
                           algorithm=None,
                           qop="auth",
                           cnonce="zf34l8eTCNX0EljCJieg4ccFBsgdOlq1",
                           nc=1,
                           username='+33900821221@osk.nokims.eu',
                           password='nsnims2008')
    log.info(params)
    assert params['response'] == 'afc145874b3545922d46de9ecf55ed8e'
    log.warning("Digest authentication test passed\n")

# ----------------------------------
    nonce=base64.b64encode(binascii.unhexlify('a5ac4954f5b6c81ac25d2d8fbf8da281272fc04023e60000517530451bd73895'))
    K=b'alice\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    
    password,ik,ck = SIPRequest.AKA(nonce, K)
    log.info("password=%s", password)
    log.info("ik=%s", ik)
    log.info("ck=%s", ck)

    assert password == binascii.unhexlify('bd5c708ee326b965')
    assert ik == binascii.unhexlify('b87a8e0392ab4cb8aeb29669d87d0518')
    assert ck == binascii.unhexlify('b4eb9c3b6b10ce98f6dfe36ca8ccdcb6')
    log.warning("AKA test passed\n")

# ----------------------------------
    register = SIPMessage.frombytes(b'''REGISTER sip:ims.mnc001.mcc208.3gppnetwork.org SIP/2.0\r
Expires: 600000\r
Authorization: Digest username="alice@ims.mnc001.mcc208.3gppnetwork.org",realm="ims.mnc001.mcc208.3gppnetwork.org",uri="sip:ims.mnc001.mcc208.3gppnetwork.org",nonce="",response="",algorithm=AKAv1-MD5\r
Security-Client: ipsec-3gpp;prot=esp;mod=trans;spi-c=10525;spi-s=27264;port-c=14803;port-s=20917;alg=hmac-md5-96;ealg=null\r
From: <sip:alice@ims.mnc001.mcc208.3gppnetwork.org>;tag=1dd771f8\r
To: <sip:alice@ims.mnc001.mcc208.3gppnetwork.org>\r
Call-ID: 60e6ee92b282327e@5.5.0.13\r
CSeq: 1 REGISTER\r
Max-Forwards: 70\r
Contact: <sip:alice@5.5.0.13:5060>\r
Require: sec-agree\r
Proxy-Require: sec-agree\r
Supported: sec-agree,path\r
User-Agent: Samsung IMS 5.0\r
Via: SIP/2.0/UDP 5.5.0.13:5060;branch=z9hG4bK5f8f754b;transport=UDP;rport\r
Route: <sip:193.252.231.243:5060;lr>\r
Content-Length: 0\r
\r
''')
    log.info("\n%s", register)
    resp = SIPMessage.frombytes(b'''SIP/2.0 401 Unauthorized - Challenging the UE\r
From: <sip:alice@ims.mnc001.mcc208.3gppnetwork.org>;tag=1dd771f8\r
To: <sip:alice@ims.mnc001.mcc208.3gppnetwork.org>;tag=faeec13323cf344e1125761a979ec21b-6877\r
Call-ID: 60e6ee92b282327e@5.5.0.13\r
CSeq: 1 REGISTER\r
Via: SIP/2.0/UDP 5.5.0.13:5060;branch=z9hG4bK5f8f754b;transport=UDP;rport=5060\r
Path: <sip:term@pcscf.ims.mnc001.mcc208.3gppnetwork.org:5060;lr>\r
Service-Route: <sip:orig@scscf.ims.mnc001.mcc208.3gppnetwork.org:6060;lr>\r
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, PUBLISH, MESSAGE, INFO\r
Server: Sip EXpress router (2.1.0-dev1 OpenIMSCore (x86_64/linux))\r
Content-Length: 0\r
Warning: 392 193.252.231.243:6060 "Noisy feedback tells:  pid=20527 req_src_ip=193.252.231.243 req_src_port=4060 in_uri=sip:scscf.ims.mnc001.mcc208.3gppnetwork.org:6060 out_uri=sip:scscf.ims.mnc001.mcc208.3gppnetwork.org:6060 via_cnt==3"\r
WWW-Authenticate: Digest realm="ims.mnc001.mcc208.3gppnetwork.org", nonce="KBdnIyppR5T1v4wsr0DCIKvGvtjeMAAAAbJwt4v710I=", algorithm=AKAv1-MD5, qop="auth,auth-int"\r
Security-Server: ipsec-3gpp; ealg=null; alg=hmac-md5-96; spi-c=5008; spi-s=5009; port-c=34432; port-s=37529; prot=esp; mod=trans; q=0.1\r
\r
''')
    log.info("\n%s", resp)
    auth = Header.Header.parse(b'''Authorization: Digest username="alice@ims.mnc001.mcc208.3gppnetwork.org",realm="ims.mnc001.mcc208.3gppnetwork.org",nonce="KBdnIyppR5T1v4wsr0DCIKvGvtjeMAAAAbJwt4v710I=",algorithm=AKAv1-MD5,uri="sip:ims.mnc001.mcc208.3gppnetwork.org",response="079d8ec52db706b0d3fa80a2e4003156",qop=auth,nc=00000001,cnonce="bcffc432c12c64e0"''')[0]

    test = register.authenticationheader(resp,
                                   cnonce=auth.params['cnonce'],
                                   K=b'alice\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                   username='alice@ims.mnc001.mcc208.3gppnetwork.org')
    assert test.header is not None
    testparams = test.header.params
    refparams = auth.params
    for k in refparams:
        ref = str(refparams[k])
        test = str(testparams[k])
        assert ref==test
    log.warning("Message parsing + Digest AKA authentication test passed\n")
