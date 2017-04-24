# coding: utf-8

import re
import base64
import hashlib
import logging
import copy
import random
import string

from . import SIPBNF
from . import Header


CRLF = b'\r\n'
STATUS_LINE_RE = re.compile(b'(?:\r\n|^)SIP/2.0 (?P<code>[1-7]\d\d) (?P<reason>.+)\r\n', re.IGNORECASE)
REQUEST_LINE_RE = re.compile(b'''(?:\r\n|^)(?P<method>[A-Za-z0-9.!%*_+`'~-]+) (?P<requesturi>[^ ]+) SIP/2.0\r\n''', re.IGNORECASE)
CONTENT_LENGTH_RE = re.compile(b'\r\n(?:Content-length|l)[ \t]*:\s*(?P<length>\d+)\s*(\r\n|$)', re.IGNORECASE)
UNFOLDING_RE = re.compile(b'[ \t]*\r\n[ \t]+')
class DecodeInfo:
    def __init__(self, buf):
        self.buf = buf
        self.klass = None; self.startline = None;
        self.istart = None; self.iheaders = None; self.iblank = None; self.ibody = None; self.iend = None
        self.contentlength = None
        self.parsingerrors = []

    def is_ok(self):
        return self.istart is not None and self.iend is not None and self.iend <= len(self.buf)

    def finish(self):
        rawheaders=self.buf[self.iheaders:self.iblank]
        body=self.buf[self.ibody:self.iend]
        if isinstance(self.buf, bytearray):
            del self.buf[:self.iend]
        headers = Header.Headers(rawheaders, strictparsing=False)
        if self.klass == SIPResponse:
            return SIPResponse(self.code, *headers.getlist(), reason=self.reason, body=body)
        elif self.klass == SIPRequest:
            return SIPRequest(self.requesturi, *headers.getlist(), body=body, method=self.method)
        else:
            return self.klass(self.requesturi, *headers.getlist(), body=body, method=self.method)

class SIPMessage(object):
    @staticmethod
    def frombytes(buf):
        decodeinfo = SIPMessage.predecode(buf)
        if decodeinfo.is_ok():
            return decodeinfo.finish()
        return None
    
    @staticmethod
    def predecode(buf):
        decodeinfo = DecodeInfo(buf)

        # Valid messages:
        #  -valid status line + CRLF
        #  -optionals header, each ending with CRLF
        #  -a blank line (CRLF)
        #  -optional body
        
        # Decoding start-line
        statusline = STATUS_LINE_RE.search(buf)
        requestline = REQUEST_LINE_RE.search(buf)
        if not statusline and not requestline:
            return decodeinfo
        s_start = statusline.start() if statusline else len(buf)
        r_start = requestline.start() if requestline else len(buf)
        if s_start < r_start:
            try:
                reason = statusline.group('reason')
                decodeinfo.reason = reason.decode('utf-8')
            except UnicodeError as err:
                decodeinfo.parsingerrors.append("UTF-8 encoding error ({} {!r}) in Reason-Phrase: {!r}".format(err.reason, err.object[err.start:err.end], reason))
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
                decodeinfo.parsingerrors.append("ASCII encoding error in Request-URI: {!r}".format(requesturi))
                return decodeinfo
            decodeinfo.requesturi = requesturi
            decodeinfo.istart = r_start
            decodeinfo.iheaders =  requestline.end()
            decodeinfo.method = requestline.group('method').decode('ascii')
            decodeinfo.klass = SIPRequest.SIPrequestclasses.get(decodeinfo.method.upper(), SIPRequest)
        
        # Separating Headers from Body
        endofheaders = buf.find(CRLF+CRLF, decodeinfo.istart)
        if endofheaders == -1:
            m = CONTENT_LENGTH_RE.search(buf, pos=decodeinfo.iheaders-2)
        else:
            decodeinfo.iblank = endofheaders+2
            decodeinfo.ibody = decodeinfo.iblank+2
            m = CONTENT_LENGTH_RE.search(buf, pos=decodeinfo.iheaders-2, endpos=decodeinfo.iblank)

        # Finding Content-Length
        if m:
            contentheader = m.group(0).strip()
            contentheader = UNFOLDING_RE.sub(b' ', contentheader)
            if not b'\r' in contentheader and not b'\n' in contentheader:
                decodeinfo.contentlength = int(m.group('length'))
                if decodeinfo.ibody:
                    decodeinfo.iend = decodeinfo.ibody + decodeinfo.contentlength

        return decodeinfo
    
    def __init__(self, *headers, body):
        if body is None:
            self.body = b''
        elif isinstance(body, str):
            self.body = body.encode('utf8')
        elif isinstance(body, bytes):
            self.body = body
        else:
            raise TypeError("body should be of type str or bytes")
        self._headers = Header.Headers(*headers)

        cl = Header.Content_Length(length=len(self.body))
        self._headers.add(cl)
        

    def addheaders(self, *headers):
        return self._headers.add(*headers)

    def getheaders(self, *names):
        return self._headers.getlist(*names)

    def hasheader(self, name):
        try:
            dummy = self._headers.getfirst(name)
            return True
        except:
            pass
        return False

    def getheader(self, name):
        return self._headers.getfirst(name)

    def popheaders(self, *names):
        return self._headers.poplist(*names)

    def popheader(self, name):
        return self._headers.popfirst(name)

    def tobytes(self, headerform='nominal'):
        ret = [self.startline(), b'\r\n']
        for header in self.getheaders():
            ret.append(header.tobytes(headerform))
            ret.append(b'\r\n')
        ret.append(b'\r\n')
        ret.append(self.body)
        return b''.join(ret)

    def __str__(self):
        return self.tobytes().decode('utf-8')

class SIPResponse(SIPMessage):
    defaultreasons = {100:'Trying', 180:'Ringing', 181:'Call is Being Forwarded', 182:'Queued', 183:'Session in Progress', 199:'Early Dialog Terminated', 200:'OK', 202:'Accepted', 204:'No Notification', 300:'Multiple Choices', 301:'Moved Permanently', 302:'Moved Temporarily', 305:'Use Proxy', 380:'Alternative Service', 400:'Bad Request', 401:'Unauthorized', 402:'Payment Required', 403:'Forbidden', 404:'Not Found', 405:'Method Not Allowed', 406:'Not Acceptable', 407:'Proxy Authentication Required', 408:'Request Timeout', 409:'Conflict', 410:'Gone', 411:'Length Required', 412:'Conditional Request Failed', 413:'Request Entity Too Large', 414:'Request-URI Too Long', 415:'Unsupported Media Type', 416:'Unsupported URI Scheme', 417:'Unknown Resource-Priority', 420:'Bad Extension', 421:'Extension Required', 422:'Session Interval Too Small', 423:'Interval Too Brief', 424:'Bad Location Information', 428:'Use Identity Header', 429:'Provide Referrer Identity', 430:'Flow Failed', 433:'Anonymity Disallowed', 436:'Bad Identity-Info', 437:'Unsupported Certificate', 438:'Invalid Identity Header', 439:'First Hop Lacks Outbound Support', 470:'Consent Needed', 480:'Temporarily Unavailable', 481:'Call/Transaction Does Not Exist', 482:'Loop Detected.', 483:'Too Many Hops', 484:'Address Incomplete', 485:'Ambiguous', 486:'Busy Here', 487:'Request Terminated', 488:'Not Acceptable Here', 489:'Bad Event', 491:'Request Pending', 493:'Undecipherable', 494:'Security Agreement Required', 500:'Server Internal Error', 501:'Not Implemented', 502:'Bad Gateway', 503:'Service Unavailable', 504:'Server Time-out', 505:'Version Not Supported', 513:'Message Too Large', 580:'Precondition Failure', 600:'Busy Everywhere', 603:'Decline', 604:'Does Not Exist Anywhere', 606:'Not Acceptable'}
    def __init__(self, code, *headers, body=None, reason=None, **kw):
        SIPMessage.__init__(self, *headers, body=body)
        self.code = code
        self.familycode = code // 100
        self.reason = reason if reason is not None else self.defaultreasons.get(code, '')

    def startline(self):
        return 'SIP/2.0 {} {}'.format(self.code, self.reason).encode('utf-8')

class RequestMeta(type):
    @staticmethod
    def __prepare__(name, bases, **dikt):
        return dict(method=name)
    def __init__(cls, name, bases, dikt):
        if name != 'SIPRequest':
            SIPRequest.SIPrequestclasses[name] = cls
        super(RequestMeta, cls).__init__(name, bases, dikt)
        
class SIPRequest(SIPMessage, metaclass=RequestMeta):
    SIPrequestclasses = {}
    def __init__(self, uri, *headers, body=None, method=None, **kw):
        SIPMessage.__init__(self, *headers, body=body)
        if isinstance(uri, SIPBNF.URI):
            self.uri = copy.deepcopy(uri)
        else:
            try:
                self.uri = SIPBNF.URI(uri)
            except:
                raise ValueError("{!r} is not a valid Request-URI".format(uri))
        if method is not None:
           self.method = method 

    def startline(self):
        return '{} {} SIP/2.0'.format(self.method, self.uri).encode('utf-8')

    def addauthorization(self, response, nc=1, cnonce=None, **kwargs):
        for authenticate in response.getheaders('WWW-Authenticate', 'Proxy-Authenticate'):
            if authenticate.scheme.lower() == 'digest':
                params = self.digest(realm = authenticate.params.get('realm'),
                                     username = kwargs.pop('username'),
                                     nonce = authenticate.params.get('nonce'),
                                     algorithm = authenticate.params.get('algorithm'),
                                     qop=authenticate.params.get('qop'),
                                     nc=nc,
                                     cnonce=cnonce or ''.join((random.choice(string.ascii_letters) for _ in range(20))),
                                     **kwargs)
                if authenticate._name == 'WWW-Authenticate':
                    auth=Header.Authorization(scheme=authenticate.scheme, params=params)
                else:
                    auth=Header.Proxy_Authorization(scheme=authenticate.scheme, params=params)
                self.addheaders(auth)

    def digest(self, *, realm, nonce, algorithm, cnonce, qop, nc, username, password):
        uri = str(self.uri)
        params = dict(realm = realm,
                      uri = uri,
                      username = username,
                      nonce = nonce,
                      algorithm = algorithm,
                      qop=qop,
        )
        algorithm = algorithm.lower() if algorithm else None
        if algorithm is not None:
            if algorithm not in ('md5', 'md5-sess'):
                pass
            if cnonce is None:
                pass
        qop = qop.lower() if qop else None
        if qop and qop not in ('auth', 'auth-int'):
            pass
        
        ha1 = self.md5hash(username, realm, password)
        if algorithm == 'md5-sess':
            ha1 = self.md5hash(ha1, nonce, cnonce)
            params.update(cnonce=cnonce)
            
        if not qop or qop == 'auth':
            ha2 = self.md5hash(self.method, uri)
        else:
            ha2 = self.md5hash(self.method, uri, md5hash(self.body))

        if not qop:
            response = self.md5hash(ha1, nonce, ha2)
        else:
            response = self.md5hash(ha1, nonce, "{:08x}".format(nc), cnonce, qop, ha2)
            params.update(cnonce=cnonce, nc=nc)
        params.update(response=response)
        return params

    def md5hash(self, *params):
        s = b':'.join((param.encode('utf-8') if isinstance(param, str) else param for param in params))
        return hashlib.md5(s).hexdigest()

    
class REGISTER(SIPRequest):
    pass
class INVITE(SIPRequest):
    def ack(self, response):
        if response.familycode == 1:
            raise ValueError("cannot build an ACK from a 1xx response")
        ack = ACK(self.uri, *self.getheaders('from', 'cseq', 'call-id', 'via'), self.getheader('to'))
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
    import sys

    register = REGISTER('sip:osk.nokims.eu')
    print(register)
    print(SIPRequest.SIPrequestclasses)
    resp = register.digest(realm="osk.nokims.eu",
                           uri='sip:osk.nokims.eu',
                           nonce="7800e38558e368911AQ8918b7eeaf71a794f910eafbdb376e8848d",
                           algorithm=None,
                           qop="auth",
                           cnonce="zf34l8eTCNX0EljCJieg4ccFBsgdOlq1",
                           nc=1,
                           username='+33900821221@osk.nokims.eu',
                           password='nsnims2008')
    print(resp)
    assert resp == 'afc145874b3545922d46de9ecf55ed8e'

