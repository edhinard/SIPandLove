#! /usr/bin/python3
# coding: utf-8

import re
import collections


CRLF = b'\r\n'
STATUS_LINE_RE = re.compile(b'(?:\r\n|^)SIP/2.0 (?P<code>[1-7]\d\d) (?P<reason>.+)\r\n', re.IGNORECASE)
REQUEST_LINE_RE = re.compile(b'(?:\r\n|^)(?P<method>[A-Z]+) (?P<requesturi>[^ ]+) SIP/2.0\r\n', re.IGNORECASE)
CONTENT_LENGTH_RE = re.compile(b'\r\n(?:Content-length|l)[ \t]*:\s*(?P<length>\d+)\s*(\r\n|$)', re.IGNORECASE)
UNFOLDING_RE = re.compile(b'[ \t]*' + CRLF + b'[ \t]+')
class DecodeInfo:
    def __init__(self, buf):
        self.buf = buf
        self.klass = None; self.params = None;
        self.istart = None; self.iheaders = None; self.iblank = None; self.ibody = None; self.iend = None
        self.contentlength = None

    def finish(self):
        message = self.klass(**self.params, rawheaders=self.buf[self.iheaders:self.iblank], body=self.buf[self.ibody:self.iend])
        return message


class SIPMessage:
    @staticmethod
    def frombytes(buf):
        decodeinfo = SIPMessage.predecode(buf)
        if decodeinfo.istart is not None and decodeinfo.iend is not None:
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
        statusline  = STATUS_LINE_RE.search(buf)
        requestline = REQUEST_LINE_RE.search(buf)
        if not statusline and not requestline:
            return decodeinfo
        s_start = statusline.start() if statusline else len(buf)
        r_start = requestline.start() if requestline else len(buf)
        if s_start < r_start:
            decodeinfo.istart = s_start
            decodeinfo.iheaders =  statusline.end()
            decodeinfo.klass = SIPResponse
            decodeinfo.params = {'code':int(statusline.group('code')), 'reason':statusline.group('reason')}
        else:
            decodeinfo.istart = r_start
            decodeinfo.iheaders =  requestline.end()
            decodeinfo.klass = SIPRequest
            decodeinfo.params = {'method':requestline.group('method'), 'requesturi':requestline.group('requesturi')}
        
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

    def __init__(self, **kwargs):
        print("-----\nSIPMessage.init({})".format(kwargs))
        self.headers = collections.OrderedDict()
        headers = kwargs.pop('headers', None)
        if headers:
            for k,v in headers.items():
                self.headers[k] = v
        self.body = b''
        rawheaders = kwargs.pop('rawheaders', None)
        if rawheaders:
            # Unfolding the headers and spliting them
            unfoldedrawheaders = UNFOLDING_RE.sub(b' ', rawheaders)
            for h in unfoldedrawheaders.split(CRLF):
                print(h)
                try:
                    header,value = map(bytes.strip, h.split(b':', maxsplit=1))
                except:
                    continue # empty lines or bad header are ignored
                self.headers[header] = value

        for key,value in kwargs.items():
            setattr(self, key, value)
        print("{}\n-----\n\n".format(self.headers))

    def tobytes(self):
        ret = [self.startline(), b'\r\n']
        self.headers[b'Content-Length'] = str(len(self.body)).encode('ascii')
        for k,v in self.headers.items():
            ret.append(b'%s: %s\r\n' % (k,v))
        ret.append(b'\r\n')
        ret.append(self.body)
        return b''.join(ret)

class SIPResponse(SIPMessage):
    defaultreasons = {100:b'Trying', 180:b'Ringing', 181:b'Call is Being Forwarded', 182:b'Queued', 183:b'Session in Progress', 199:b'Early Dialog Terminated', 200:b'OK', 202:b'Accepted', 204:b'No Notification', 300:b'Multiple Choices', 301:b'Moved Permanently', 302:b'Moved Temporarily', 305:b'Use Proxy', 380:b'Alternative Service', 400:b'Bad Request', 401:b'Unauthorized', 402:b'Payment Required', 403:b'Forbidden', 404:b'Not Found', 405:b'Method Not Allowed', 406:b'Not Acceptable', 407:b'Proxy Authentication Required', 408:b'Request Timeout', 409:b'Conflict', 410:b'Gone', 411:b'Length Required', 412:b'Conditional Request Failed', 413:b'Request Entity Too Large', 414:b'Request-URI Too Long', 415:b'Unsupported Media Type', 416:b'Unsupported URI Scheme', 417:b'Unknown Resource-Priority', 420:b'Bad Extension', 421:b'Extension Required', 422:b'Session Interval Too Small', 423:b'Interval Too Brief', 424:b'Bad Location Information', 428:b'Use Identity Header', 429:b'Provide Referrer Identity', 430:b'Flow Failed', 433:b'Anonymity Disallowed', 436:b'Bad Identity-Info', 437:b'Unsupported Certificate', 438:b'Invalid Identity Header', 439:b'First Hop Lacks Outbound Support', 470:b'Consent Needed', 480:b'Temporarily Unavailable', 481:b'Call/Transaction Does Not Exist', 482:b'Loop Detected.', 483:b'Too Many Hops', 484:b'Address Incomplete', 485:b'Ambiguous', 486:b'Busy Here', 487:b'Request Terminated', 488:b'Not Acceptable Here', 489:b'Bad Event', 491:b'Request Pending', 493:b'Undecipherable', 494:b'Security Agreement Required', 500:b'Server Internal Error', 501:b'Not Implemented', 502:b'Bad Gateway', 503:b'Service Unavailable', 504:b'Server Time-out', 505:b'Version Not Supported', 513:b'Message Too Large', 580:b'Precondition Failure', 600:b'Busy Everywhere', 603:b'Decline', 604:b'Does Not Exist Anywhere', 606:b'Not Acceptable'}
    def __init__(self, code, reason=None, **kwargs):
        SIPMessage.__init__(self, **kwargs)
        self.code = code
        if reason is None:
            self.reason = self.defaultreasons.get(code, '')
        else:
            self.reason = reason

    def startline(self):
        return b'SIP/2.0 %d %s' % (self.code, self.reason)

    def __str__(self):
        ret = ['<SIPResponse {} {}'.format(self.code, self.reason)]
        for k,v in self.headers.items():
            ret.append('{}={}'.format(k,v))
        return ' '.join(ret) + '>'
        

class SIPRequest(SIPMessage):
    def __new__(cls, method, requesturi, **kwargs):
        if method == 'REGISTER':
            return super().__new__(REGISTER)
        elif method == 'INVITE':
            return super().__new__(INVITE)
        else:
            return super().__new__(cls)
        
    def __init__(self, method, requesturi, **kwargs):
        SIPMessage.__init__(self, **kwargs)
        self.method = method
        self.requesturi = requesturi

    def startline(self):
        return b'%s %s SIP/2.0' % (self.method, self.requesturi)

    def response(self, code, reason=None):
        return SIPResponse(code, reason, headers=self.headers)

class REGISTER(SIPRequest):
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

