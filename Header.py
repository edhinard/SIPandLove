#coding: utf-8

import re
import copy
import logging
import itertools
log = logging.getLogger('Header')

from . import SIPBNF
from . import Utils


   
#
# Ordered collection of headers in a SIP message
class Headers:
    HEADERSEP_RE = re.compile(b'\r\n(?![ \t])')
    firstnames = ['via', 'route', 'from', 'to', 'contact', 'expires', 'call-id', 'cseq', 'max-forward']
    lastnames = ['allow', 'content-type', 'content-length']
    
    def __init__(self, *headers, strictparsing=True):
        self._headers = {}
        self.add(*headers, strictparsing=strictparsing)
        
    def add(self, *headers, strictparsing=True):
        headers = Headers.parse(*headers, strictparsing=strictparsing)
        for header in headers:
            self._headers.setdefault(header._indexname, []).append(header)

    def addifmissing(self, *headers, strictparsing=True):
        headers = Headers.parse(*headers, strictparsing=strictparsing)
        for header in headers:
            l = self._headers.setdefault(header._indexname, [])
            if len(l) == 0:
                l.append(header)

    def replaceoradd(self, *headers, strictparsing=True):
        headers = Headers.parse(*headers, strictparsing=strictparsing)
        replaced = set()
        for header in headers:
            index = header._indexname
            if not index in replaced:
                self._headers[index] = []
                replaced.add(index)
            self._headers[index].append(header)

    @staticmethod
    def parse(*headers, strictparsing):
        newheaders = []
        for header in headers:
            #
            # Already formed Headers are copied and added to the list
            #
            if isinstance(header, Header):
                newheaders.append(copy.deepcopy(header))
                continue

            
            #
            # Other are bytes sequence that must be decoded
            #
            if isinstance(header, (bytes, bytearray)):
                headerbytes = bytes(header)
            elif isinstance(header, str):
                headerbytes = header.encode('utf-8')
            else:
                raise TypeError("headers should be of type str or bytes")

            #
            # Split bytes sequence on \r\n not followed by a blank
            #
            for rawheader in Headers.HEADERSEP_RE.split(b'\r\n' + headerbytes):
                if not rawheader: continue

                #
                # Parse the header
                #
                try:
                    newheaders.extend(Header.parse(rawheader))
                except Exception as error:
                    if strictparsing:
                        raise
                    else:
                        log.warning(error)
        return newheaders

    def list(self, *names):
        if not names:
            names = list(self._headers.keys())
        else:
            names = [Header.index(name) for name in names if Header.index(name) in self._headers.keys()]
        firstnames = [Header.index(name) for name in Headers.firstnames if Header.index(name) in names]
        lastnames = [Header.index(name) for name in Headers.lastnames if Header.index(name) in names]
        return list(itertools.chain(*itertools.chain([self._headers[name] for name in firstnames]),
                                    *itertools.chain([self._headers[name] for name in names if name not in firstnames and name not in lastnames]),
                                    *itertools.chain([self._headers[name] for name in lastnames])))

    def first(self, name):
        return self._headers.get(Header.index(name), [None])[0]

    def pop(self, name):
        index = Header.index(name)
        l = self._headers.get(index)
        if l is None:
            return None
        if len(l) == 1:
            del self._headers[index]
        return l.pop(0)
 
    def tobytes(self, headerform='nominal'):
        return b'\r\n'.join([header.tobytes(headerform) for header in self._headers] + [b''])

#
# Metaclass that automatically adds the attributes
#   -_name
#   -_alias
#   -_args
#   -_parse
#   -_multiple
#   -_display
#  to each Header subclass based on the definition in SIPBNF.py
#
# And collect all headers in dict Header.SIPheaderclasses
#
# Exemple:
#  class Content_Length(Header):
#      pass
#  cl = Content_Length()
#  assert cl._name == 'Content-Length'
#  assert cl._args == SIPBNF.Content_LengthArgs
#  assert cl._alias == SIPBNF.Content_LengthAlias or None
#  assert cl._parse == SIPBNF.Content_LengthParse
#  assert cl._multiple == SIPBNF.Content_LengthMultiple or False
#  assert cl._display == SIPBNF.Content_LengthDisplay
class HeaderMeta(type):
    def __new__(cls, name, bases, dikt):
        if name != 'Header':
            dikt['_args'] = getattr(SIPBNF, name + 'Args')
            dikt['_parse'] = staticmethod(getattr(SIPBNF, name + 'Parse'))
            dikt['_display'] = getattr(SIPBNF, name + 'Display')
            dikt['_multiple'] = getattr(SIPBNF, name + 'Multiple', False)
            dikt['_name'] = name.replace('_', '-')
            dikt['_indexname'] = dikt['_name'].lower()
        return super(HeaderMeta, cls).__new__(cls, name, bases, dikt)
    def __init__(cls, name, bases, dikt):
        if name != 'Header':
            siplowername = name.replace('_', '-').lower()
            Header.SIPheaderclasses[siplowername] = cls
            alias = getattr(SIPBNF, name + 'Alias', None)
            if alias:
                Header.SIPheaderclasses[alias.lower()] = cls
                Header.SIPAliases[alias.lower()] = siplowername
        super(HeaderMeta, cls).__init__(name, bases, dikt)

class Byteheader():
    _indexname = None
    def __init__(self, raw):
        self.raw = raw
    def tobytes(self, headerform=None):
        return self.raw
    
        
# Base class of SIP headers
class Header(metaclass=HeaderMeta):
    SIPheaderclasses = {}
    SIPAliases = {}

    @staticmethod
    def index(name):
        name = name.lower()
        return Header.SIPAliases.get(name, name)
    
    def __init__(self, name=None, **kwargs):
        if not getattr(self, '_name', False):
            assert name
            self._name = name
            self._indexname = Header.index(name)
        self._originalname = name or self._name
        if getattr(self, '_args', False):
            if not set(self._args) == set(kwargs.keys()):
                raise ValueError("Expected parameters for {!r} constructor are {!r}, got {!r}".format(self._name, self._args, tuple(kwargs.keys())))
        else:
            self._args = kwargs.keys()
        self.__dict__.update(kwargs)
        log.debug("New header {}".format(self))

    HEADER_RE = re.compile(b'^([a-zA-Z-.!%*_+`\'~]+)[ \t]*:(.*)$', flags=re.DOTALL)
    UNFOLDING_RE = re.compile(b'[ \t]*\r\n[ \t]+')
    @staticmethod
    def parse(rawheader):
        #
        # A line starting with a # becomes an unparsed Byte Header
        #
        if rawheader[0] == b'#'[0]:
            log.debug("{!r} --> Byteheader".format(rawheader))
            return [Byteheader(rawheader[1:])]

        #
        # Parse the header: "^ name [WSP] HCOLON value $"
        #
        try:
            name,value = Header.HEADER_RE.match(rawheader).groups()
            value = value.strip()
        except:
            log.warning("Parsing error on {}: does not match 'name HCOLON value'".format(rawheader))
            raise Exception("Expecting: header-name HCOLON header-value. Got {}".format(rawheader))
        name = name.decode('utf-8')

        #
        # Unfold the value (replace (blanks) + \r\n + blank(s) with SPACE)
        #
        value = Header.UNFOLDING_RE.sub(b' ', value)
        if value[0] == b'#'[0]:
            #
            # A value starting with a # is not parsed
            #
            cls = None
            value = value[1:]
        else:
            #
            # Check that header value is a valid UTF-8 string
            #  and find header type according to the name
            try:
                value = value.decode('utf-8')
            except:
                log.warning("Parsing error on {!r}: not an UTF-8 string".format(value))
                raise
            cls = Header.SIPheaderclasses.get(name.lower())

        #
        # Parse the header
        #
        if cls:
            try:
                if cls._multiple:
                    argsgenerator = cls._parse(value)
                    headers = [cls(name=name, **args) for args in argsgenerator]
                else:
                    args = cls._parse(value)
                    headers = [cls(name=name, **args)]
            except Exception as e:
                log.warning("Parsing error on {!r}: {}".format(rawheader, e))
                raise
        else:
            headers = [Header(name=name, value=value)]
        log.debug("{!r} --> {}".format(rawheader, headers))
        return headers
        
    def __str__(self):
        try:
            str = self.tobytes().decode('utf-8')
            if not '\x00' in str:
                return str
        except:
            pass
        return "{}: {}".format(self._name, repr(self._display())[2:-1])
    def __iter__(self):
        for k in self._args:
            yield k, getattr(self,k)
    def __repr__(self):
        return '{}({!r})'.format(self._name, dict(self))
    _args = ('value',)
    def _display(self):
        return self.value
    def tobytes(self, headerform='nominal'):
        if headerform == 'nominal':
            name = self._name
        elif headerform == 'short':
            name = self._alias or self._name
        elif headerform == 'original':
            name = self._originalname
        else:
            raise ValueError("unknown headerform {!r}".format(headerform))
        name = name.encode('utf-8')
        value = self._display()
        if isinstance(value, str):
            value = value.encode('utf-8')
        return b'%s: %s' % (name, value)


#class Accept(Header):
#    pass

#class Accept_Encoding(Header):
#    pass

#class Accept_Language(Header):
#    pass

#class Alert_Info(Header):
#    pass

#class Allow(Header):
#    pass

class Authentication_Info(Header):
    pass

class Authorization(Header):
    pass

class Call_ID(Header):
    def __init__(self, callid, name=None):
        super().__init__(name, callid=callid)

#class Call_Info(Header):
#    pass

class CFT: # common constructor to Contact From To
    def __init__(self, address, display=None, params={}, name=None):
        if not isinstance(address, SIPBNF.URI):
            address = SIPBNF.URI(address)
        if not isinstance(params, Utils.ParameterDict):
            params = Utils.ParameterDict(params)
        Header.__init__(self, name, address=address, display=display, params=params)

class Contact(CFT, Header):
    pass

#class Content_Disposition(Header):
#    pass

#class Content_Encoding(Header):
#    pass

#class Content_Language(Header):
#    pass

class Content_Length(Header):
    pass

class Content_Type(Header):
    def __init__(self, type, subtype=None, params={}, name=None):
        if subtype is None:
            assert '/' in type
            type,subtype = type.split('/', 1)
        if not isinstance(params, Utils.ParameterDict):
            params = Utils.ParameterDict(params)
        super().__init__(name, type=type, subtype=subtype, params=params)

class CSeq(Header):
    pass

#class Date(Header):
#    pass

#class Error_Info(Header):
#    pass

class Expires(Header):
    pass

class From(CFT, Header):
    pass

#class In_Reply_To(Header):
#    pass

class Max_Forwards(Header):
    pass

#class MIME_Version(Header):
#    pass

class Min_Expires(Header):
    pass

#class Organization(Header):
#    pass

#class Priority(Header):
#    pass

class Proxy_Authenticate(Header):
    pass

class Proxy_Authorization(Header):
    pass

#class Proxy_Require(Header):
#    pass

#class Record_Route(Header):
#    pass

#class Reply_To(Header):
#    pass

#class Require(Header):
#    pass

#class Retry_After(Header):
#    pass

class Route(Header):
    pass

#class Server(Header):
#    pass

#class Subject(Header):
#    pass

#class Supported(Header):
#    pass

#class Timestamp(Header):
#    pass

class To(CFT, Header):
    pass

#class Unsupported(Header):
#    pass

#class User_Agent(Header):
#    pass

class Via(Header):
    pass

#class Warning(Header):
#    pass

class WWW_Authenticate(Header):
    pass

class Security_Client(Header):
    pass
class Security_Server(Header):
    pass
class Security_Verify(Header):
    pass


if __name__ == '__main__':
    import sys
    
    goodheaders = (
        'Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',
        'Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',
        'Via: SIP /2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',
        'Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',
        'Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',
        'Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb',
        'Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb',
        'Route: une route bien droite <sip:172.20.56.7;lr>',
        'Route: "route 123" <sip:172.20.56.7;lr>',
        'Route: "une route" <sip:172.20.56.7;lr>, "deuxième route" <sip:172.20.56.7>   ,   \t "et de trois" <sip:172.20.56.7>,<sip:172.20.56.7>',
        'Route: "\xc3\xa0 droite ou \xc3\xa0 gauche ?" <sip:172.20.56.7;lr>',
        'Route: "\xc8\x81\xe8\x80\x81\xf0\x90\x80\x80  \xf4\x80\x80\x80  " <sip:172.20.56.7;lr>',
        'Max-Forwards: 70',
        '''Max-Forwards:\r
 70''',
        'From: <sip:alice@toto.com>;tag',
        'From: sip:alice@toto.com;lr',
#        'From: sip:alice@toto.com; lr',
        'From: "with quote \\" and backslash \\\\." <sip:172.20.56.7;lr>',
        'From: sip:+33960700014@sip.osk.com;lr;toto=titi',
        'From: sip:+33960700014@sip.osk.com;lr;toto=titi',
        'From: "aaaaaaaa" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto',
        'From: "bbbbb cccc èèè\u0123\u4567\u89ab\ucdef" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto',
        'From: "bbbbb cccc èèè \u1234\u5678\u9abc" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto',
        'From: <sip:+33960700014@sip.osk.com>',
        'From: <sip:+33960700014@sip.osk.com>;tag=QNUPkiWuoMCQvYGw6VvQX9tzF-.1Oa5w',
        'From: <sip:0960700011@sip.osk.com;user=phone;noa=national;srvattri=national>;tag=4lQ1i4QM',

        'v: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz',

        'To: <sip:+33960700014@sip.osk.com>',
        'To: sip:+33960700014@sip.osk.com',

        'CSeq: 60011 REGISTER',
        '''CSeq: 60011\r
      REGISTER''',

        'User-Agent: PJSUA v2.5.5 Linux-4.8.0.27/x86_64/glibc-2.24',

        'Contact: *',
        'Contact: <sip:+33960700014@172.20.35.253:6064;ob>',
        'Contact: <sip:+33960700014@172.20.35.253:6064;ob>;expires=3600',
        'Contact: <sip:+33960700014@172.20.35.253:6064>,"coucou" <sip:+33960700014@172.20.35.253:6064;ob>,sip:+33960700014@172.20.35.253:6064;ob',
        'Contact: <sip:172.20.56.7:5060;Dpt=ea7a-200;Hpt=8e52_16;CxtId=4;TRC=ffffffff-ffffffff>',
        'Expires: 300',

        'Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS',

        'Content-Length:  0',

        'Authorization: Digest username="", response="0123456789abcdef0123456789abcdef"',
        'Authorization: Digest username="a",realm="sip.osk.com"',
        'Authorization: Digest username="a", realm="sip.osk.com"\t\t ,\tnonce="",uri="sip:sip.osk.com",response=""',
        'Authorization: Toto a="a", b= b  , c\t="",d=\'d\' ,e = 8',
        'Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"',
        '''Authorization : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""''',
        'Content-Length:  0',
        'Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"',
        '''Authorization : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""''',

        'Authentication-Info: nc=00000005',
        'Authentication-Info: rspauth="ccc"',
        'Authentication-Info: rspauth=""',
        'Authentication-Info: qop=xx',
        'Authentication-Info: nextnonce="iupiuh"',
        'Authentication-Info: nc=00000005,rspauth="ccc",qop=xx,nextnonce="iupiuh"',

        'Content-Length:  0',
        'toto: titi',
        'toto:tutu',
        'Security-Server: ipsec-3gpp; ealg=null; alg=hmac-md5-96; spi-c=123; spi-s=1234; port-c=12345; port-s=123456; prot=esp; mod=trans; q=0.1'
        )


    for string in goodheaders:
        print("*",string)
        try:
            headers = Headers(string, strictparsing=True)
        except Exception as err:
            sys.exit(1)
        for header in headers.list():
            print(">",header)
            print(repr(header))
            print()
        print()
    print()
    print(Authorization(scheme='test', params=dict(a='1',b='2')))
    print(Call_ID(callid=0))
    print(Contact(display='disp', address='here', params=dict(a='1',b='2')))
    print(Content_Length(length=0))
    print(Content_Type(type='a', subtype='b', params=dict(a='1',b='2')))
    print(CSeq(seq=0, method='A'))
    print(Expires(delta=0))
    print(From(display='disp', address='here', params=dict(a='1',b='2')))
    print(Max_Forwards(max=0))
    print(Proxy_Authenticate(scheme='test', params=dict(a='1',b='2')))
    print(Proxy_Authorization(scheme='test', params=dict(a='1',b='2')))
    print(Route(display='disp', address='here', params=dict(a='1',b='2')))
    print(To(display='disp', address='here', params=dict(a='1',b='2')))
#    print(Via(protocol='A', sent_by='a', params=dict(a='1',b='2')))
    print(WWW_Authenticate(scheme='test', params=dict(a='1',b='2')))
    print()
    f=From(name='f', display='disp', address='here', params=dict(a='1',b='2'))
    print(f)
    print(repr(f))
    print(f._name)
    print(f._indexname)
    t=To(name='t', display='disp', address='here', params=dict(a='1',b='2'))
