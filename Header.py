#coding: utf-8

import re
import copy

from . import SIPBNF


class HeaderError(Exception):
    def __init__(self, msg, headerstring, name=None):
        self.msg = msg
        self.headerstring = headerstring
        self.name = name
    def __str__(self):
        if self.name is not None:
            pre = "Bad {} header".format(self.name)
        else:
            pre = "Bad header"
        return "{}. {}: {!r}".format(pre, self.msg, self.headerstring)
    
#
# Ordered collection of headers in a SIP message
class Headers:
    HEADERSEP_RE = re.compile(b'\r\n(?![ \t])')
    
    def __init__(self, *headers, strictparsing=True):
        self._headers = []
        self.errors = []
        self.add(*headers, strictparsing=strictparsing)
        
    def add(self, *headers, strictparsing=True):
        for header in headers:
            #
            # Already formed Headers are copied and added to the list
            #
            if isinstance(header, Header):
                self._headers.append(copy.deepcopy(header))
                continue

            
            #
            # Other are bytes sequence that must be decoded
            #
            if isinstance(header, bytes):
                headerbytes = header
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
                    headers = Header.parse(rawheader)
                except HeaderError as error:
                    if strictparsing:
                        raise
                    else:
                        self.errors.append(error)
                else:
                    self._headers.extend(headers)

    def getlist(self, *names):
        for index in self.indices(*names):
            yield self._headers[index]
    def getfirst(self, name):
        return self._headers[self.firstindex(name)]

    def poplist(self, *names):
        shift = 0
        for index in self.indices(*names):
            yield self._headers.pop(index-shift)
            shift += 1
    def popfirst(self, name):
        return self._headers.pop(self.firstindex(name))

    def indices(self, *names):
        if not names:
            yield from range(len(self._headers))
        lookup = []
        once = []
        for name in names:
            firstonly = False
            if name.startswith('_'):
                firstonly = True
                name = name[1:]
            name = name.lower()
            if name in Header.SIPAliases:
                name = Header.SIPAliases[name]
            if not name in lookup:
                lookup.append(name)
                if firstonly:
                    once.append(name)
        for i,name in enumerate((header._indexname for header in self._headers)):
            if name in lookup:
                yield i
                if name in once:
                    lookup.remove(name)
    def firstindex(self, name):
        try:
            index = next(self.indices(name))
        except StopIteration:
            raise Exception("No Header with that name {!r}".format(name))
        return index
 
    def tobytes(self, headerform='nominal'):
        return b'\r\n'.join([header.tobytes(headerform) for header in self._headers] + [b''])
    
    def __iter__(self):
        return iter(self._headers)
    def __contains__(self, name):
        name = name.lower()
        for header in self._headers:
            if header._indexname == name:
                return True
        return False

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
    
# Base class of SIP headers
class Header(metaclass=HeaderMeta):
    SIPheaderclasses = {}
    SIPAliases = {}
    
    def __init__(self, name=None, **kwargs):
        if not getattr(self, '_name', False):
            assert name
            self._name = name
            self._indexname = name.lower()
        self._originalname = name or self._name
        if getattr(self, '_args', False):
            if not set(self._args) == set(kwargs.keys()):
                raise ValueError("Expected parameters for {!r} constructor are {!r}, got {!r}".format(self._name, self._args, tuple(kwargs.keys())))
        else:
            self._args = kwargs.keys()
        self.__dict__.update(kwargs)

    HEADER_RE = re.compile('^([a-zA-Z-.!%*_+`\'~]+)[ \t]*:(.*)$', flags=re.DOTALL)
    UNFOLDING_RE = re.compile('[ \t]*\r\n[ \t]+')
    @staticmethod
    def parse(rawheader):
        #
        # Check that header content is a valid UTF-8 string
        #
        try:
            headerstring = rawheader.decode('utf-8')
        except UnicodeError as err:
            raise HeaderError("UTF-8 encoding error ({} {!r})".format(err.reason, err.object[err.start:err.end]), rawheader)

        #
        # Parse the header: "^ name [WSP] : value $"
        #
        try:
            name,value = Header.HEADER_RE.match(headerstring).groups()
            value = value.strip()
        except:
            raise HeaderError("Expecting: header-name HCOLON header-value", headerstring)

        #
        # Unfold the value (replace (blanks) + \r\n + blank(s) with SPACE)
        #
        value = Header.UNFOLDING_RE.sub(' ', value)
                
        #
        # Parse the value according to the name of the header
        #
        cls = Header.SIPheaderclasses.get(name.lower())
        if cls:
            error = None
            try:
                if cls._multiple:
                    argsgenerator = cls._parse(value)
                    headers = ([cls(name, **args) for args in argsgenerator])
                else:
                    args = cls._parse(value)
                    headers = [cls(name, **args)]
            except SIPBNF.ParseException as e:
                raise HeaderError("Error at pos {}".format(e.pos), value, cls._name)
            except Exception as e:
                raise HeaderError(str(e), value, cls._name)
        else:
            headers = [Header(name=name, value=value)]
        return headers
        
    def __str__(self):
        return self.tobytes().decode('utf-8')
    def __repr__(self):
        args = ("{}={!r}".format(k,getattr(self,k)) for k in self._args)
        return '{}({})'.format(self._name, ", ".join(args))
    _args = ('value',)
    def _display(self):
        return self.value
    def tobytes(self, headerform='nominal'):
        if headerform == 'nominal':
            key = self._name
        elif headerform == 'short':
            key = self._alias or self._name
        elif headerform == 'original':
            key = self._originalname
        else:
            raise ValueError("unknown headerform {!r}".format(headerform))
        return "{}: {}".format(key, self._display()).encode('utf-8')


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

#class Authentication_Info(Header):
#    pass

class Authorization(Header):
    pass

class Call_ID(Header):
    pass

#class Call_Info(Header):
#    pass

class Contact(Header):
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
    pass

class CSeq(Header):
    pass

#class Date(Header):
#    pass

#class Error_Info(Header):
#    pass

class Expires(Header):
    pass

class From(Header):
    pass

#class In_Reply_To(Header):
#    pass

class Max_Forwards(Header):
    pass

#class MIME_Version(Header):
#    pass

#class Min_Expires(Header):
#    pass

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

class To(Header):
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


if __name__ == '__main__':
    import sys
    
    goodheaders = """Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP /2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb\r
Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb\r
Route: "route" <sip:172.20.56.7;lr>\r
Route: "une route" <sip:172.20.56.7;lr>\r
Route: "\xc3\xa0 droite ou \xc3\xa0 gauche ?" <sip:172.20.56.7;lr>\r
Route: "\xc8\x81\xe8\x80\x81\xf0\x90\x80\x80  \xf4\x80\x80\x80  " <sip:172.20.56.7;lr>\r
Route: une route bien droite <sip:172.20.56.7;lr>\r
Max-Forwards: 70\r
Max-Forwards:\r
 70\r
From: sip:alice@toto.com;lr\r
From: sip:alice@toto.com; lr\r
From: "with quote \\" and backslash \\\\." <sip:172.20.56.7;lr>\r
From: <sip:alice@toto.com>;tag\r
From: sip:+33960700014@sip.osk.com;lr;toto=titi\r
From: sip:+33960700014@sip.osk.com;lr;toto=titi\r
From: "aaaaaaaa" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto\r
From: "bbbbb cccc èèè\u0123\u4567\u89ab\ucdef" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto\r
From: "bbbbb cccc èèè \u1234\u5678\u9abc" <sip:+33960700014@sip.osk.com:1;lr>;tag=dd;toto\r
From: <sip:+33960700014@sip.osk.com>\r
From: <sip:+33960700014@sip.osk.com>;tag=QNUPkiWuoMCQvYGw6VvQX9tzF-.1Oa5w\r
v: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
To: <sip:+33960700014@sip.osk.com>\r
To: sip:+33960700014@sip.osk.com\r
CSeq: 60011 REGISTER\r
CSeq: 60011\r
      REGISTER\r
User-Agent: PJSUA v2.5.5 Linux-4.8.0.27/x86_64/glibc-2.24\r
Contact: *\r
Contact: <sip:+33960700014@172.20.35.253:6064;ob>\r
Contact: <sip:+33960700014@172.20.35.253:6064>,"coucou" <sip:+33960700014@172.20.35.253:6064;ob>,sip:+33960700014@172.20.35.253:6064;ob\r
Expires: 300\r
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r
Content-Length:  0\r
Authorization: Digest username="", response="0123456789abcdef0123456789abcdef"\r
Authorization: Digest username="a",realm="sip.osk.com"\r
Authorization: Digest username="a", realm="sip.osk.com"\t\t ,\tnonce="",uri="sip:sip.osk.com",response=""\r
Authorization: Toto a="a", b= b  , c\t="",d=\'d\' ,e = 8\r
Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"\r
Authorization : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""\r
Content-Length:  0\r
Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"\r
Authorization : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""\r
Content-Length:  0\r
toto: titi\r
toto:tutu"""


    try:
        headers = Headers(goodheaders, strictparsing=True)
    except HeaderError as err:
        print(err)
        sys.exit(1)
    for header in headers:
        print(repr(header))
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
    print(Via(protocol='A', sent_by='a', params=dict(a='1',b='2')))
    print(WWW_Authenticate(scheme='test', params=dict(a='1',b='2')))
    print()
    f=From(name='f', display='disp', address='here', params=dict(a='1',b='2'))
    print(f)
    print(repr(f))
    print(f._name)
    print(f._indexname)
    t=To(name='t', display='disp', address='here', params=dict(a='1',b='2'))
