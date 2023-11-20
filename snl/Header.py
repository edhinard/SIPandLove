from . import SIPBNF
from . import Utils

import re
import copy
import logging
import itertools
log = logging.getLogger('Header')


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
            hl = self._headers.setdefault(header._indexname, [])
            if len(hl) == 0:
                hl.append(header)

    def replaceoradd(self, *headers, strictparsing=True):
        headers = Headers.parse(*headers, strictparsing=strictparsing)
        replaced = set()
        for header in headers:
            index = header._indexname
            if index not in replaced:
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
                if not rawheader:
                    continue

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
        return list(itertools.chain(
            *itertools.chain([self._headers[name] for name in firstnames]),
            *itertools.chain([self._headers[name] for name in names
                              if name not in firstnames and name not in lastnames]),
            *itertools.chain([self._headers[name] for name in lastnames])))

    def first(self, name):
        return self._headers.get(Header.index(name), [None])[0]

    def pop(self, name):
        index = Header.index(name)
        hl = self._headers.get(index)
        if hl is None:
            return None
        if len(hl) == 1:
            del self._headers[index]
        return hl.pop(0)

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
            dikt['_alias'] = getattr(SIPBNF, name + 'Alias', None)
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
                raise ValueError(
                    "Expected parameters for {!r} constructor are {!r}, got {!r}"
                    .format(self._name, self._args, tuple(kwargs.keys())))
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
            name, value = Header.HEADER_RE.match(rawheader).groups()
            value = value.strip()
        except Exception:
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
            except UnicodeDecodeError:
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
            if '\x00' not in str:
                return str
        except Exception:
            pass
        return "{}: {}".format(self._name, repr(self._display())[2:-1])

    def __iter__(self):
        for k in self._args:
            yield k, getattr(self, k)
    _args = ('value',)

    def __repr__(self):
        return '{}({!r})'.format(self._name, dict(self))

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


# class Accept(Header):
#    pass

# class Accept_Encoding(Header):
#    pass

# class Accept_Language(Header):
#    pass

# class Alert_Info(Header):
#    pass

# class Allow(Header):
#    pass


class Authentication_Info(Header):
    pass


class Authorization(Header):
    pass


class Call_ID(Header):
    def __init__(self, callid, name=None):
        super().__init__(name, callid=callid)

# class Call_Info(Header):
#    pass


class CFT:  # common constructor to Contact From To
    def __init__(self, address, display=None, params={}, name=None):
        if not isinstance(address, SIPBNF.URI):
            address = SIPBNF.URI(address)
        if not isinstance(params, Utils.ParameterDict):
            params = Utils.ParameterDict(params)
        Header.__init__(self, name, address=address, display=display, params=params)


class Contact(CFT, Header):
    pass

# class Content_Disposition(Header):
#    pass

# class Content_Encoding(Header):
#    pass

# class Content_Language(Header):
#    pass


class Content_Length(Header):
    pass


class Content_Type(Header):
    def __init__(self, type, subtype=None, params={}, name=None):
        if subtype is None:
            assert '/' in type
            type, subtype = type.split('/', 1)
        if not isinstance(params, Utils.ParameterDict):
            params = Utils.ParameterDict(params)
        super().__init__(name, type=type, subtype=subtype, params=params)


class CSeq(Header):
    pass

# class Date(Header):
#    pass

# class Error_Info(Header):
#    pass


class Expires(Header):
    pass


class From(CFT, Header):
    pass

# class In_Reply_To(Header):
#    pass


class Max_Forwards(Header):
    pass

# class MIME_Version(Header):
#    pass


class Min_Expires(Header):
    pass

# class Organization(Header):
#    pass

# class Priority(Header):
#    pass


class Proxy_Authenticate(Header):
    pass


class Proxy_Authorization(Header):
    pass

# class Proxy_Require(Header):
#    pass

# class Record_Route(Header):
#    pass

# class Reply_To(Header):
#    pass

# class Require(Header):
#    pass

# class Retry_After(Header):
#    pass


class Route(Header):
    pass

# class Server(Header):
#    pass

# class Subject(Header):
#    pass

# class Supported(Header):
#    pass

# class Timestamp(Header):
#    pass


class To(CFT, Header):
    pass

# class Unsupported(Header):
#    pass

# class User_Agent(Header):
#    pass


class Via(Header):
    pass

# class Warning(Header):
#    pass


class WWW_Authenticate(Header):
    pass


class Security_Client(Header):
    pass


class Security_Server(Header):
    pass


class Security_Verify(Header):
    pass


class Event(Header):
    def __init__(self, event, params={}, name=None):
        if not isinstance(params, Utils.ParameterDict):
            params = Utils.ParameterDict(params)
        super().__init__(event=event, params=params)


class Allow_Events(Header):
    pass


class Subscription_State(Header):
    pass


class P_Associated_URI(Header):
    pass


class P_Called_Party_ID(Header):
    pass
