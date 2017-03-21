#coding: utf-8

import re
import SIPBNF
import types


#
# Case insensitive dictionnary for headername -> header class        
class HeaderDict(dict):
    def get(self, key, default=None):
        key = key.replace('-', '_').lower()
        for k in self.keys():
            if key == k.lower():
                return super(HeaderDict, self).__getitem__(k)
        return default
    def __contains__(self, key):
        return self.get(key) is not None
    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

#
# Ordered collection of headers in a SIP message
class Headers:
    SIPheaderclasses = HeaderDict()
    
    HEADERSEP_RE = re.compile(b'\r\n(?![ \t])')
    HEADER_RE = re.compile('^([a-zA-Z-.!%*_+`\'~]+)[ \t]*:(.*)$', flags=re.DOTALL)
    UNFOLDING_RE = re.compile('[ \t]*\r\n[ \t]+')
    
    def __init__(self, rawheaders):
        self.headers = []
        self.errors = []

        #
        # Split headers on \r\n not followed by a blank
        #
        for headerstring in Headers.HEADERSEP_RE.split(rawheaders):
            if not headerstring: continue

            #
            # Check that header content is a valid UTF-8 string
            #
            try:
                headerstring = headerstring.decode('utf-8')
                pass
            except UnicodeError as err:
                self.errors.append("UTF-8 encoding error ({} {!r}) in header: {}".format(err.reason, err.object[err.start:err.end], headerstring))
                continue

            #
            # Parse the header: "^ name [WSP] : value $"
            #
            try:
                name,value = Headers.HEADER_RE.match(headerstring).groups()
                value = value.strip()
            except:
                self.errors.append("Bad header. Expecting: header-name HCOLON header-value. Got: {!r}".format(headerstring))
                continue

            #
            # Unfold the value (replace (blanks) + \r\n + blank(s) with SPACE)
            #
            value = Headers.UNFOLDING_RE.sub(' ', value)

            #
            # Parse the value according to the name of the header
            #
            cls = Headers.SIPheaderclasses.get(name)
            if cls:
                try:
                    res = cls.parse(value)
                    if isinstance(res, types.GeneratorType):
                        self.headers.extend([cls(name, **p) for p in res])
                    else:
                        self.headers.append(cls(name, **res))
                except SIPBNF.ParseException as e:
                    self.errors.append("Bad {} header. Error at pos {}: ".format(cls.name, e.pos))
                    continue
            else:
                self.headers.append(Header(name=name, value=value))

    def append(self, header):
        if not isinstance(header, Header):
            raise TypeError("expecting a Header. Got a {}".format(type(header)))
        self.headers.append(header)
    def extend(self, headers):
        for header in headers:
            self.append(header)
    def find(self, name):
        if not isinstance(name, str):
            raise TypeError("str expected as index")
        name = name.lower()
        for i,header in enumerate(self.headers):
            if header.indexname == name:
                return i
        return -1
                
    def __len__(self):
        return len(self.headers)
    def __getitem__(self, nameorindex):
        if isinstance(nameorindex, int):
            return self.headers[nameorindex]
        elif isinstance(nameorindex, str):
            name = nameorindex.lower()
            return (header for header in self.headers if header.indexname == name)
        raise TypeError("keys must be integers or str")
    def __setitem__(self, index, header):
        if not isinstance(header, Header):
            raise TypeError("values must be Header")
        if not isinstance(index, int):
            raise TypeError("keys must be integers")
        self.headers[index] = header
    def __delitem__(self, nameorindex):
        if isinstance(nameorindex, int):
            del self.headers[nameorindex]
        elif isinstance(nameorindex, str):
            name = nameorindex.lower()
            index = 0
            while index < len(self.headers):
                if self.headers[index].indexname == name:
                    del self.headers[index]
                else:
                    index += 1
        raise TypeError("keys must be integers or str")
    def __iter__(self):
        return iter(self.headers)
    def __contains__(self, name):
        name = name.lower()
        for header in self.headers:
            if header.indexname == name:
                return True
        return False
                
#
# Metaclass that automatically adds the attributes
#   -name
#   -alias
#   -parse
#   -display
#  to each Header subclass based on the definition in SIPBNF.py
#
# And collect all headers in HeaderDict Headers.SIPheaderclasses
#
# Exemple:
#  class Content_Length(Header):
#      pass
#  cl = Content_Length()
#  assert cl.name == 'Content-Length'
#  assert c.alias == SIPBNF.Content_LengthAlias # == 'l'
#  assert c.parse == SIPBNF.Content_LengthParse
#  assert c.display == SIPBNF.Content_LengthDisplay
#
#  assert Content_Length == Headers.SIPheaderclasses.get('conteNT-lENgth')
class HeaderMeta(type):
    def __new__(cls, name, bases, dikt):
        if name != 'Header':
            parse = getattr(SIPBNF, name + 'Parse')
            dikt['parse'] = staticmethod(parse)
            display = getattr(SIPBNF, name + 'Display')
            dikt['display'] = display
            dikt['name'] = name.replace('_', '-')
            dikt['indexname'] = dikt['name'].lower()
        return super(HeaderMeta, cls).__new__(cls, name, bases, dikt)
    def __init__(cls, name, bases, dikt):
        if name != 'Header':
            Headers.SIPheaderclasses[name] = cls
            alias = getattr(SIPBNF, name + 'Alias', None)
            if alias:
                Headers.SIPheaderclasses[alias] = cls
        super(HeaderMeta, cls).__init__(name, bases, dikt)
    
# Base class of SIP headers
class Header(metaclass=HeaderMeta):
    def __init__(self, name=None, **kwargs):
        if not getattr(self, 'name', None):
            assert name
            self.name = name
            self.indexname = name.lower()
        self._originalname = name or self.name
        self.__dict__.update(kwargs)
        self._args = kwargs
#    def __str__(self):
#        return self.tobytes().decode('utf-8')
    def __repr__(self):
        args = ("{}={!r}".format(k,v) for k,v in self._args.items())
        return '{}({})'.format(self.name, ", ".join(args))
    def display(self):
        return self.value
    def tobytes(self, headerform='nominal'):
        if headerform == 'nominal':
            key = self.name
        elif headerform == 'short':
            key = self.alias or self.name
        elif headerform == 'original':
            key = self._originalname
        else:
            raise ValueError("unknown headerform {!r}".format(headerform))
        return "{}: {}".format(key, self.display()).encode('utf-8')


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

#class Authorization(Header):
#    pass

#class Call_ID(Header):
#    pass

#class Call_Info(Header):
#    pass

#class Contac(Header):
#    pass

#class Content_Disposition(Header):
#    pass

#class Content_Encoding(Header):
#    pass

#class Content_Language(Header):
#    pass

class Content_Length(Header):
    pass

#class Content_Type(Header):
#    pass

#class CSeq(Header):
#    pass

#class Date(Header):
#    pass

#class Error_Info(Header):
#    pass

#class Expires(Header):
#    pass

#class From(Header):
#    pass

#class In_Reply_To(Header):
#    pass

#class Max_Forwards(Header):
#    pass

#class MIME_Version(Header):
#    pass

#class Min_Expires(Header):
#    pass

#class Organization(Header):
#    pass

#class Priority(Header):
#    pass

#class Proxy_Authenticate(Header):
#    pass

#class Proxy_Authorization(Header):
#    pass

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

#class Route(Header):
#    pass

#class Server(Header):
#    pass

#class Subject(Header):
#    pass

#class Supported(Header):
#    pass

#class Timestamp(Header):
#    pass

#class To(Header):
#    pass

#class Unsupported(Header):
#    pass

#class User_Agent(Header):
#    pass

class Via(Header):
    pass

#class Warning(Header):
#    pass

#class WWW_Authenticate(Header):
#    pass


if __name__ == '__main__':
    rawheader = b"""Via:\r
v: X\r
Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Via: SIP /2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz, SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
\tVia: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
\tVia: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb\r
Call-ID: HrbWx6Jsr2g57PkBrkQwweCZyXCyM7xb\r
Route: "route" <sip:172.20.56.7;lr>\r
Route: "une route" <sip:172.20.56.7;lr>\r
Route: "\xc3\xa0 droite ou \xc3\xa0 gauche ?" <sip:172.20.56.7;lr>\r
Route: "\xc8\x81\xe8\x80\x81\xf0\x90\x80\x80  \xf4\x80\x80\x80  " <sip:172.20.56.7;lr>\r
Route: une route bien droite <sip:172.20.56.7;lr>\r
Route\r
 : <sip:172.20.56.7;lr>\r
Route\r
 : <sip:172.20.56.7;lr>\r
Max-Forwards: 70\r
Max-Forwards:\r
 70\r
From: <sip:+33960700014@sip.osk.com>;tag=QNUPkiWuoMCQvYGw6VvQX9tzF-.1Oa5w\r
v: SIP/2.0/UDP 172.20.35.253:6064;rport;branch=z9hG4bKPjHpg0F53qjaD1TynDvA.ahs2u7dszKZlz\r
To: <sip:+33960700014@sip.osk.com>\r
CSeq: 60011 REGISTER\r
CSeq: 60011\r
      REGISTER\r
User-Agent: PJSUA v2.5.5 Linux-4.8.0.27/x86_64/glibc-2.24\r
Contact: <sip:+33960700014@172.20.35.253:6064;ob>\r
Expires: 300\r
Expires\r
: 300\r
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r
Content-Length:  0\r
Authorization: Digest username=""\r
Authorization: Digest username="a",realm="sip.osk.com"\r
Authorization: Digest username="a", realm="sip.osk.com"\t\t ,\tnonce="",uri="sip:sip.osk.com",response=""\r
Authorization: Toto a="a", b= b  , c\t="",d=\'d\' ,e = 8\r
Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"\r
Authorization\r
 : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""\r
Content-Length:  0\r
Authorization: Digest uri="sip:sip.osk.com", username="+33960700014@sip.osk.com"\r
Authorization\r
 : Digest username="+33960700014@sip.osk.com", realm="sip.osk.com", nonce="", uri="sip:sip.osk.com",\r
\t       response=""\r
Content-Length:  0\r
toto: titi\r
toto:tutu"""
    for header in Headers(rawheader):
        print(header)
