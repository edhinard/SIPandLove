# coding: utf-8

import re
import collections

import SIPBNF
import Header


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
        return self.istart is not None and self.iend is not None and self.iend <= len(buf)

    def finish(self):
        rawheaders=self.buf[self.iheaders:self.iblank]
        body=self.buf[self.ibody:self.iend]
        if isinstance(self.buf, bytearray):
            del self.buf[:self.iend]
        if self.klass == SIPResponse:
            return SIPResponse(code=self.code, reason=self.reason, rawheaders=rawheaders, body=body)
        elif self.klass == SIPRequest:
            return SIPRequest(method=self.method, requesturi=self.requesturi, rawheaders=rawheaders, body=body)

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
            decodeinfo.requesturi = SIPBNF.URI(requesturi)
            decodeinfo.istart = r_start
            decodeinfo.iheaders =  requestline.end()
            decodeinfo.klass = SIPRequest
            decodeinfo.method = requestline.group('method').decode('ascii')
        
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

    def __init__(self, *, rawheaders=b'', body=b'', headers=[]):
        self.body = body
        self.headers = Header.Headers(rawheaders)
        self.headers.extend(headers)

    def tobytes(self, headerform='nominal'):
        ret = [self.startline(), b'\r\n']
        cl = Header.Content_Length(length=len(self.body))
        i = self.headers.find('Content-Length')
        if i != -1:
            self.headers[i] = cl
        else:
            self.headers.append(cl)
        for header in self.headers:
            ret.append(header.tobytes(headerform))
            ret.append(b'\r\n')
        ret.append(b'\r\n')
        ret.append(self.body)
        return b''.join(ret)

    def __str__(self):
        return self.tobytes().decode('utf-8')

class SIPResponse(SIPMessage):
    defaultreasons = {100:'Trying', 180:'Ringing', 181:'Call is Being Forwarded', 182:'Queued', 183:'Session in Progress', 199:'Early Dialog Terminated', 200:'OK', 202:'Accepted', 204:'No Notification', 300:'Multiple Choices', 301:'Moved Permanently', 302:'Moved Temporarily', 305:'Use Proxy', 380:'Alternative Service', 400:'Bad Request', 401:'Unauthorized', 402:'Payment Required', 403:'Forbidden', 404:'Not Found', 405:'Method Not Allowed', 406:'Not Acceptable', 407:'Proxy Authentication Required', 408:'Request Timeout', 409:'Conflict', 410:'Gone', 411:'Length Required', 412:'Conditional Request Failed', 413:'Request Entity Too Large', 414:'Request-URI Too Long', 415:'Unsupported Media Type', 416:'Unsupported URI Scheme', 417:'Unknown Resource-Priority', 420:'Bad Extension', 421:'Extension Required', 422:'Session Interval Too Small', 423:'Interval Too Brief', 424:'Bad Location Information', 428:'Use Identity Header', 429:'Provide Referrer Identity', 430:'Flow Failed', 433:'Anonymity Disallowed', 436:'Bad Identity-Info', 437:'Unsupported Certificate', 438:'Invalid Identity Header', 439:'First Hop Lacks Outbound Support', 470:'Consent Needed', 480:'Temporarily Unavailable', 481:'Call/Transaction Does Not Exist', 482:'Loop Detected.', 483:'Too Many Hops', 484:'Address Incomplete', 485:'Ambiguous', 486:'Busy Here', 487:'Request Terminated', 488:'Not Acceptable Here', 489:'Bad Event', 491:'Request Pending', 493:'Undecipherable', 494:'Security Agreement Required', 500:'Server Internal Error', 501:'Not Implemented', 502:'Bad Gateway', 503:'Service Unavailable', 504:'Server Time-out', 505:'Version Not Supported', 513:'Message Too Large', 580:'Precondition Failure', 600:'Busy Everywhere', 603:'Decline', 604:'Does Not Exist Anywhere', 606:'Not Acceptable'}
    def __init__(self, code, rawheaders=b'', body=b'', *, reason=None, headers=[]):
        SIPMessage.__init__(self, rawheaders=rawheaders, body=body, headers=headers)
        self.code = code
        self.familycode = code // 100
        if reason is None:
            self.reason = self.defaultreasons.get(code, '')
        else:
            self.reason = reason

    def startline(self):
        return 'SIP/2.0 {} {}'.format(self.code, self.reason).encode('utf-8')

#    def __str__(self):
#        ret = ['<SIPResponse {} {}'.format(self.code, self.reason)]
#        for header in self.headers:
#            ret.append(repr(header))
#        return ' '.join(ret) + '>'
        

class SIPRequest(SIPMessage):
    def __new__(cls, requesturi, rawheaders=b'', body=b'', *, method=None, headers=()):
        klass = globals().get(method)
        if issubclass(klass, SIPRequest):
            return SIPMessage.__new__(klass)
        else:
            return SIPMessage.__new__(cls)
        
    def __init__(self, requesturi, rawheaders=b'', body=b'', *, method=None, headers=()):
        SIPMessage.__init__(self, rawheaders=rawheaders, body=body, headers=headers)
        self.method = method
        self.requesturi = requesturi

    def startline(self):
        return '{} {} SIP/2.0'.format(self.method, self.requesturi).encode('utf-8')

    def response(self, code, reason=None):
        return SIPResponse(code, reason, headers=self.headers)

#    def __str__(self):
#        ret = ['<{} {}'.format(self.method, self.requesturi)]
#        for header in self.headers:
#            ret.append(repr(header))
#        return ' '.join(ret) + '>'
    
class REGISTER(SIPRequest):
    def authenticate(self, auth, password):
        pass
class INVITE(SIPRequest):
    pass
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

    buf = bytearray()
    for line in sys.stdin.buffer:
        buf += line
        #print(line)

        message = SIPMessage.frombytes(buf)
        if message:
            #print(message.headers.parsingerrors)
#            if isinstance(message, SIPRequest):
#                print(message.method, message.requesturi)
#            else:
#                print(message.code, message.reason)
            print(message)
            print()

        
