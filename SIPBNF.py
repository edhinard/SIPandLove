#coding: utf-8

import pyparsing as pp

from .Utils import quote,unquote,ParameterDict

class ParseException(Exception):
    def __init__(self, msg, pos):
        self.msg = msg
        self.pos = pos

class Parser:
    def __init__(self, ppParser):
        self.parser = ppParser + pp.StringEnd()
        self.parser.leaveWhitespace()
        self.parser.setWhitespaceChars('')
        self.parser.parseWithTabs()
    def parse(self, string):
        try:
            return self.parser.parseString(string)
        except pp.ParseException as e:
            raise ParseException(e.msg, pos=e.col-1)

#   Even though an arbitrary number of parameter pairs may be attached to
#   a header field value, any given parameter-name MUST NOT appear more
#   than once.
#
#   When comparing header fields, field names are always case-
#   insensitive.  Unless otherwise stated in the definition of a
#   particular header field, field values, parameter names, and parameter
#   values are case-insensitive.


#   Several rules are incorporated from RFC 2396 [5] but are updated to
#   make them compliant with RFC 2234 [10].  These include:
#
#      reserved    =  ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+"
#                     / "$" / ","
#      unreserved  =  alphanum / mark
#      mark        =  "-" / "_" / "." / "!" / "~" / "*" / "'"
#                     / "(" / ")"
#      escaped     =  "%" HEXDIG HEXDIG
HEXDIG = pp.hexnums
unreserved  =  pp.alphanums + '-_.!~*\'()'
escaped = pp.Literal('%') + pp.Word(HEXDIG, exact=2)
reserved =  ';/?:@&=+$,'


#   SIP header field values can be folded onto multiple lines if the
#   continuation line begins with a space or horizontal tab.  All linear
#   white space, including folding, has the same semantics as SP.  A
#   recipient MAY replace any linear white space with a single SP before
#   interpreting the field value or forwarding the message downstream.
#   This is intended to behave exactly as HTTP/1.1 as described in RFC
#   2616 [8].  The SWS construct is used when linear white space is
#   optional, generally between tokens and separators.
#
#      LWS  =  [*WSP CRLF] 1*WSP ; linear whitespace
#      SWS  =  [LWS] ; sep whitespace
WSP = pp.Word(' \t')
LWS = WSP
SWS = pp.Optional(WSP)


#   To separate the header name from the rest of value, a colon is used,
#   which, by the above rule, allows whitespace before, but no line
#   break, and whitespace after, including a linebreak.  The HCOLON
#   defines this construct.
#
#      HCOLON  =  *( SP / HTAB ) ":" SWS
CRLF = pp.Literal('\r\n')
HCOLON = pp.Group(pp.Optional(WSP) + pp.Literal(':') + pp.Optional(WSP) + pp.Optional(CRLF) + pp.Optional(WSP))


#   The TEXT-UTF8 rule is only used for descriptive field contents and
#   values that are not intended to be interpreted by the message parser.
#   Words of *TEXT-UTF8 contain characters from the UTF-8 charset (RFC
#   2279 [7]).  The TEXT-UTF8-TRIM rule is used for descriptive field
#   contents that are n t quoted strings, where leading and trailing LWS
#   is not meaningful.  In this regard, SIP differs from HTTP, which uses
#   the ISO 8859-1 character set.
#
#      TEXT-UTF8-TRIM  =  1*TEXT-UTF8char *(*LWS TEXT-UTF8char)
#      TEXT-UTF8char   =  %x21-7E / UTF8-NONASCII
#      UTF8-NONASCII   =  %xC0-DF 1UTF8-CONT
#                      /  %xE0-EF 2UTF8-CONT
#                      /  %xF0-F7 3UTF8-CONT
#                      /  %xF8-Fb 4UTF8-CONT
#                      /  %xFC-FD 5UTF8-CONT
#      UTF8-CONT       =  %x80-BF
#
#  A CRLF is allowed in the definition of TEXT-UTF8-TRIM only as part of
#   a header field continuation.  It is expected that the folding LWS
#   will be replaced with a single SP before interpretation of the TEXT-
#   UTF8-TRIM value.
#
#   Hexadecimal numeric characters are used in several protocol elements.
#   Some elements (authentication) force hex alphas to be lower case.
#
#      LHEX  =  DIGIT / %x61-66 ;lowercase a-f
LHEX = '0123456789abcdef'


#   Many SIP header field values consist of words separated by LWS or
#   special characters.  Unless otherwise stated, tokens are case-
#   insensitive.  These special characters MUST be in a quoted string to
#   be used within a parameter value.  The word construct is used in
#   Call-ID to allow most separators to be used.
#
#      token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
#                     / "_" / "+" / "`" / "'" / "~" )
#      separators  =  "(" / ")" / "<" / ">" / "@" /
#                     "," / ";" / ":" / "\" / DQUOTE /
#                     "/" / "[" / "]" / "?" / "=" /
#                     "{" / "}" / SP / HTAB
#      word        =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
#                     "_" / "+" / "`" / "'" / "~" /
#                     "(" / ")" / "<" / ">" /
#                     ":" / "\" / DQUOTE /
#                     "/" / "[" / "]" / "?" /
#                     "{" / "}" )
token = pp.Word(pp.alphanums + '-.!%*_+`\'~', min=1)
word  = pp.Word(pp.alphanums + '-.!%*_+`\'~()<>:\\"/[]?{}', min=1)


#   When tokens are used or separators are used between elements,
#   whitespace is often allowed before or after these characters:
#
#      STAR    =  SWS "*" SWS ; asterisk
#      SLASH   =  SWS "/" SWS ; slash
#      EQUAL   =  SWS "=" SWS ; equal
#      LPAREN  =  SWS "(" SWS ; left parenthesis
#      RPAREN  =  SWS ")" SWS ; right parenthesis
#      RAQUOT  =  ">" SWS ; right angle quote
#      LAQUOT  =  SWS "<"; left angle quote
#      COMMA   =  SWS "," SWS ; comma
#      SEMI    =  SWS ";" SWS ; semicolon
#      COLON   =  SWS ":" SWS ; colon
#      LDQUOT  =  SWS DQUOTE; open double quotation mark
#      RDQUOT  =  DQUOTE SWS ; close double quotation mark
STAR = (pp.Suppress(SWS) + pp.Literal('*') + pp.Suppress(SWS))
SLASH = (pp.Suppress(SWS) + pp.Literal('/') + pp.Suppress(SWS))
EQUAL = (pp.Suppress(SWS) + pp.Literal('=') + pp.Suppress(SWS))


RAQUOT = pp.Literal(">") + pp.Suppress(SWS)
LAQUOT = pp.Suppress(SWS) + pp.Literal("<")
COMMA = pp.Suppress(SWS + pp.Literal(',') + SWS)
SEMI = pp.Suppress(SWS + pp.Literal(';') + SWS)
COLON = (pp.Suppress(SWS) + pp.Literal(':') + pp.Suppress(SWS))
DQUOTE = pp.Literal('"')
LDQUOT = SWS + DQUOTE
RDQUOT = DQUOTE + SWS


#  Comments can be included in some SIP header fields by surrounding the
#   comment text with parentheses.  Comments are only allowed in fields
#   containing "comment" as part of their field value definition.  In all
#   other fields, parentheses are considered part of the field value.
#
#      comment  =  LPAREN *(ctext / quoted-pair / comment) RPAREN
#      ctext    =  %x21-27 / %x2A-5B / %x5D-7E / UTF8-NONASCII
#                  / LWS
#
#   ctext includes all chars except left and right parens and backslash.
#   A string of text is parsed as a single word if it is quoted using
#   double-quote marks.  In quoted strings, quotation marks (") and
#   backslashes (\) need to be escaped.
#
#     quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
#      qdtext         =  LWS / %x21 / %x23-5B / %x5D-7E
#                        / UTF8-NONASCII
#
#   The backslash character ("\") MAY be used as a single-character
#   quoting mechanism only within quoted-string and comment constructs.
#   Unlike HTTP/1.1, the characters CR and LF cannot be escaped by this
#   mechanism to avoid conflict with line folding and header separation.
#
#quoted-pair  =  "\" (%x00-09 / %x0B-0C
#                / %x0E-7F)
quoted_string = pp.Suppress(SWS) + pp.quotedString


#SIP-URI          =  "sip:" [ userinfo ] hostport
#                    uri-parameters [ headers ]
#SIPS-URI         =  "sips:" [ userinfo ] hostport
#                    uri-parameters [ headers ]
#userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
#user             =  1*( unreserved / escaped / user-unreserved )
#user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
#password         =  *( unreserved / escaped /
#                    "&" / "=" / "+" / "$" / "," )
#hostport         =  host [ ":" port ]
#host             =  hostname / IPv4address / IPv6reference
#hostname         =  *( domainlabel "." ) toplabel [ "." ]
#domainlabel      =  alphanum
#                    / alphanum *( alphanum / "-" ) alphanum
#toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
#IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
#IPv6reference  =  "[" IPv6address "]"
#IPv6address    =  hexpart [ ":" IPv4address ]
#hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
#hexseq         =  hex4 *( ":" hex4)
#hex4           =  1*4HEXDIG
#port           =  1*DIGIT
#
#   The BNF for telephone-subscriber can be found in RFC 2806 [9].  Note,
#   however, that any characters allowed there that are not allowed in
#   the user part of the SIP URI MUST be escaped.
#
#uri-parameters    =  *( ";" uri-parameter)
#uri-parameter     =  transport-param / user-param / method-param
#                     / ttl-param / maddr-param / lr-param / other-param
#transport-param   =  "transport="
#                     ( "udp" / "tcp" / "sctp" / "tls"
#                     / other-transport)
#other-transport   =  token
#user-param        =  "user=" ( "phone" / "ip" / other-user)
#other-user        =  token
#method-param      =  "method=" Method
#ttl-param         =  "ttl=" ttl
#maddr-param       =  "maddr=" host
#lr-param          =  "lr"
#other-param       =  pname [ "=" pvalue ]
#pname             =  1*paramchar
#pvalue            =  1*paramchar
#paramchar         =  param-unreserved / unreserved / escaped
#param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
#
#headers         =  "?" header *( "&" header )
#header          =  hname "=" hvalue
#hname           =  1*( hnv-unreserved / unreserved / escaped )
#hvalue          =  *( hnv-unreserved / unreserved / escaped )
#hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
user = pp.OneOrMore(pp.Word(unreserved+'&=+$,;?/') ^ escaped)
password = pp.ZeroOrMore(pp.Word(unreserved+'&=+$,') ^ escaped)
userinfo = user + pp.Optional(pp.Suppress(pp.Literal(':')) + password, None) + pp.Suppress(pp.Literal('@'))
domainlabel = pp.Word(pp.alphanums, pp.alphanums + '-') + pp.Optional(pp.Word(pp.alphanums, max=1))
toplabel = pp.Word(pp.alphas, pp.alphanums + '-') + pp.Optional(pp.Word(pp.alphanums, max=1))
hostname = pp.Combine(pp.ZeroOrMore(domainlabel + pp.Literal('.')) + toplabel + pp.Optional(pp.Literal('.')))
IPv4address = pp.Combine(pp.Word(pp.nums, max=3) + pp.Literal('.') + pp.Word(pp.nums, max=3) + pp.Literal('.') + pp.Word(pp.nums, max=3) + pp.Literal('.') + pp.Word(pp.nums, max=3))
hex4 = pp.Word(HEXDIG, max=4)
hexseq =  hex4 + pp.ZeroOrMore(pp.Literal(':') + hex4)
hexpart =  hexseq ^ (hexseq + pp.Literal('::') + pp.Optional(hexseq)) ^ (pp.Literal('::') + pp.Optional(hexseq))
IPv6address =  pp.Combine(hexpart + pp.Optional(pp.Literal(':') + IPv4address))
IPv6reference = pp.Combine(pp.Literal('[') + IPv6address +pp.Literal(']'))
host =  hostname ^ IPv4address ^ IPv6reference
hostport =  host + pp.Optional(pp.Suppress(pp.Literal(':')) + pp.Word(pp.nums), '')
other_transport = token
transport_param = pp.CaselessLiteral('transport=') + (pp.CaselessLiteral('udp') ^ pp.CaselessLiteral('tcp') ^ pp.CaselessLiteral('sctp') ^ pp.CaselessLiteral('tls') ^ other_transport)
other_user =  token
user_param =  pp.CaselessLiteral('user') + pp.Literal('=') + (pp.CaselessLiteral('phone') ^ pp.CaselessLiteral('ip') ^ other_user)
method_param = pp.CaselessLiteral('method') + pp.Literal('=') + (pp.Literal('INVITE') ^ pp.Literal('ACK') ^ pp.Literal('OPTIONS') ^ pp.Literal('BYE') ^ pp.Literal('CANCEL') ^ pp.Literal('REGISTER') ^ token)
ttl_param = pp.CaselessLiteral('ttl') + pp.Literal('=') + pp.Word(pp.nums, max=3)
maddr_param = pp.CaselessLiteral('maddr') + pp.Literal('=') + host
lr_param = pp.CaselessLiteral('lr')
pvalue = pname = pp.OneOrMore(pp.Word(unreserved+'[]/:&+$') ^ escaped)
other_param = pname + pp.Optional(pp.Literal('=') + pvalue)
uri_parameter = transport_param ^ user_param ^ method_param ^ ttl_param ^ maddr_param ^ lr_param ^ other_param
uri_parameters = pp.ZeroOrMore(pp.Literal(';') + uri_parameter)
hvalue = pp.ZeroOrMore(pp.Word(unreserved+'[]/?:+$') ^ escaped)
hname = pp.OneOrMore(pp.Word(unreserved+'[]/?:+$') ^ escaped)
header = hname + pp.Literal('=') + hvalue
headers = pp.Literal('?') + header + pp.ZeroOrMore(pp.Literal('&') + header)

SIP_URI  = pp.CaselessLiteral('sip')  + pp.Suppress(pp.Literal(':')) + pp.Optional(userinfo, None) + hostport + uri_parameters + pp.Optional(headers)
SIPS_URI = pp.CaselessLiteral('sips') + pp.Suppress(pp.Literal(':'))+ pp.Optional(userinfo, None) + hostport + uri_parameters + pp.Optional(headers)


#SIP-message    =  Request / Response
#Request        =  Request-Line
#                  *( message-header )
#                  CRLF
#                  [ message-body ]
#Request-Line   =  Method SP Request-URI SP SIP-Version CRLF
#Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
#absoluteURI    =  scheme ":" ( hier-part / opaque-part )
#hier-part      =  ( net-path / abs-path ) [ "?" query ]
#net-path       =  "//" authority [ abs-path ]
#abs-path       =  "/" path-segments
#opaque-part    =  uric-no-slash *uric
#uric           =  reserved / unreserved / escaped
#uric-no-slash  =  unreserved / escaped / ";" / "?" / ":" / "@"
#                  / "&" / "=" / "+" / "$" / ","
#path-segments  =  segment *( "/" segment )
#segment        =  *pchar *( ";" param )
#param          =  *pchar
#pchar          =  unreserved / escaped /
#                  ":" / "@" / "&" / "=" / "+" / "$" / ","
#scheme         =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
#authority      =  srvr / reg-name
#srvr           =  [ [ userinfo "@" ] hostport ] !!!! @ already in userinfo !!!!
#reg-name       =  1*( unreserved / escaped / "$" / ","
#                  / ";" / ":" / "@" / "&" / "=" / "+" )
#query          =  *uric
uric = pp.ZeroOrMore(pp.Word(unreserved+reserved) ^ escaped)
opaque_part = pp.Combine(pp.OneOrMore(pp.Word(unreserved+';?:@&=+$,', unreserved+reserved) ^ escaped))
query = uric
pchar = pp.ZeroOrMore(pp.Word(unreserved+':@&=+$,') ^ escaped)
segment = pchar + pp.ZeroOrMore(pp.Literal(';') + pchar)
path_segments = segment + pp.ZeroOrMore(pp.Literal('/') + segment)
abs_path = pp.Literal('/') + path_segments
reg_name = pp.OneOrMore(pp.Word(unreserved+'$,;:@&=+') ^ escaped)
srvr = pp.Optional(pp.Optional(userinfo) + hostport)
authority = srvr ^ reg_name
net_path = pp.Literal('//') + authority + pp.Optional(abs_path)
hier_part = pp.Combine(net_path ^ abs_path) + pp.Optional(pp.Literal('?') + pp.Combine(query))
scheme = pp.Word(pp.alphas, pp.alphanums+'+-.')
absoluteURI = scheme + pp.Suppress(pp.Literal(':')) + (hier_part ^ opaque_part)
Request_URI = SIP_URI ^ SIPS_URI ^ absoluteURI

class URI:
    def __init__(self, valueorparseresult):
        if isinstance(valueorparseresult, str):
            res = Parser(Request_URI).parse(valueorparseresult)
        else:
            res = valueorparseresult
        self.scheme = res.pop(0)
        if self.scheme.startswith('sip'):
            # SIP or SIPS URI
            self.user = res.pop(0)
            if self.user is None:
                self.password = None
            else:
                self.password = res.pop(0)
            self.host = res.pop(0)
            port = res.pop(0)
            if port == '':
                self.port = None
            else:
                self.port = int(port)
            self.params = ParameterDict()
            while res and res[0] == ';':
                res.pop(0)
                k = res.pop(0)
                if res and res[0] == '=':
                    res.pop(0)
                    v = res.pop(0)
                else:
                    v = None
                self.params[k] = v
            self.headers = ParameterDict()
            if res:
                res.pop(0) # it should be a '?'
            while res:
                k = res.pop(0)
                res.pop(0) # it should be a '='
                v =res.pop(0)
                self.headers[k] = v
        else:
            # absoluteURI
            self.uri = res.pop(0)
            self.query = res.pop(0) if res else None
        assert len(res) == 0
    @property
    def userinfo(self):
        if self.user is None and self.password is None:
            return ''
        if self.password is None:
            return '{}@'.format(self.user)
        return '{}:{}@'.format(self.user or '', self.password)
    def __str__(self):
        if self.scheme.startswith('sip'):
            if self.port is None:
                hostport = self.host
            else:
                hostport = '{}:{}'.format(self.host, self.port)
            params = (';{}{}'.format(k, ('={}'.format(v) if v is not None else '') or '') for k,v in self.params.items())
            headers = ('{}={}'.format(k, v) for k,v in self.headers.items())
            return "{}:{}{}{}{}".format(self.scheme, self.userinfo, hostport, ''.join(params), '&'.join(headers) or '')
        else:
            return "{}:{}{}".format(self.scheme, self.uri, "?{}".format(self.query) if self.query is not None else '')
    def __repr__(self):
        if self.scheme.startswith('sip'):
            return "URI(scheme={!r}, userinfo={!r}, host={!r}, port={!r}, params={!r}, headers={!r})".format(self.scheme, self.userinfo, self.host, self.port, self.params, self.headers)
        else:
            return "URI(scheme={!r}, uri={!r}, query={!r})".format(self.scheme, self.uri, self.query)
#SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
#
#message-header  =  (Accept
#                /  Accept-Encoding
#                /  Accept-Language
#                /  Alert-Info
#                /  Allow
#                /  Authentication-Info
#                /  Authorization
#                /  Call-ID
#                /  Call-Info
#                /  Contact
#                /  Content-Disposition
#                /  Content-Encoding
#                /  Content-Language
#                /  Content-Length
#                /  Content-Type
#                /  CSeq
#                /  Date
#                /  Error-Info
#                /  Expires
#                /  From
#                /  In-Reply-To
#                /  Max-Forwards
#                /  MIME-Version
#                /  Min-Expires
#                /  Organization
#                /  Priority
#                /  Proxy-Authenticate
#                /  Proxy-Authorization
#                /  Proxy-Require
#                /  Record-Route
#                /  Reply-To
#                /  Require
#                /  Retry-After
#                /  Route
#                /  Server
#                /  Subject
#                /  Supported
#                /  Timestamp
#                /  To
#                /  Unsupported
#                /  User-Agent
#                /  Via
#                /  Warning
#                /  WWW-Authenticate
#                /  extension-header) CRLF
#
#INVITEm           =  %x49.4E.56.49.54.45 ; INVITE in caps
#ACKm              =  %x41.43.4B ; ACK in caps
#OPTIONSm          =  %x4F.50.54.49.4F.4E.53 ; OPTIONS in caps
#BYEm              =  %x42.59.45 ; BYE in caps
#CANCELm           =  %x43.41.4E.43.45.4C ; CANCEL in caps
#REGISTERm         =  %x52.45.47.49.53.54.45.52 ; REGISTER in caps
#Method            =  INVITEm / ACKm / OPTIONSm / BYEm
#                     / CANCELm / REGISTERm
#                     / extension-method
#extension-method  =  token
Method = pp.Literal('INVITE') ^ pp.Literal('ACK') ^ pp.Literal('OPTIONS') ^ pp.Literal('BYE') ^ pp.Literal('CANCEL') ^ pp.Literal('REGISTER') ^ token


#Response          =  Status-Line
#                     *( message-header )
#                     CRLF
#                     [ message-body ]
#
#Status-Line     =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
#Status-Code     =  Informational
#               /   Redirection
#               /   Success
#               /   Client-Error
#               /   Server-Error
#               /   Global-Failure
#               /   extension-code
#extension-code  =  3DIGIT
#Reason-Phrase   =  *(reserved / unreserved / escaped
#                   / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
#
#Informational  =  "100"  ;  Trying
#              /   "180"  ;  Ringing
#              /   "181"  ;  Call Is Being Forwarded
#              /   "182"  ;  Queued
#              /   "183"  ;  Session Progress
#
#Success  =  "200"  ;  OK
#
#Redirection  =  "300"  ;  Multiple Choices
#            /   "301"  ;  Moved Permanently
#            /   "302"  ;  Moved Temporarily
#            /   "305"  ;  Use Proxy
#            /   "380"  ;  Alternative Service
#
#Client-Error  =  "400"  ;  Bad Request
#             /   "401"  ;  Unauthorized
#             /   "402"  ;  Payment Required
#             /   "403"  ;  Forbidden
#             /   "404"  ;  Not Found
#             /   "405"  ;  Method Not Allowed
#             /   "406"  ;  Not Acceptable
#             /   "407"  ;  Proxy Authentication Required
#             /   "408"  ;  Request Timeout
#             /   "410"  ;  Gone
#             /   "413"  ;  Request Entity Too Large
#             /   "414"  ;  Request-URI Too Large
#             /   "415"  ;  Unsupported Media Type
#             /   "416"  ;  Unsupported URI Scheme
#             /   "420"  ;  Bad Extension
#             /   "421"  ;  Extension Required
#             /   "423"  ;  Interval Too Brief
#             /   "480"  ;  Temporarily not available
#             /   "481"  ;  Call Leg/Transaction Does Not Exist
#             /   "482"  ;  Loop Detected
#             /   "483"  ;  Too Many Hops
#             /   "484"  ;  Address Incomplete
#             /   "485"  ;  Ambiguous
#             /   "486"  ;  Busy Here
#             /   "487"  ;  Request Terminated
#             /   "488"  ;  Not Acceptable Here
#             /   "491"  ;  Request Pending
#             /   "493"  ;  Undecipherable
#
#Server-Error  =  "500"  ;  Internal Server Error
#             /   "501"  ;  Not Implemented
#             /   "502"  ;  Bad Gateway
#             /   "503"  ;  Service Unavailable
#             /   "504"  ;  Server Time-out
#             /   "505"  ;  SIP Version not supported
#             /   "513"  ;  Message Too Large
#
#Global-Failure  =  "600"  ;  Busy Everywhere
#               /   "603"  ;  Decline
#               /   "604"  ;  Does not exist anywhere
#               /   "606"  ;  Not Acceptable

#Accept         =  "Accept" HCOLON
#                   [ accept-range *(COMMA accept-range) ]
#accept-range   =  media-range *(SEMI accept-param)
#media-range    =  ( "*/*"
#                  / ( m-type SLASH "*" )
#                  / ( m-type SLASH m-subtype )
#                  ) *( SEMI m-parameter )
#accept-param   =  ("q" EQUAL qvalue) / generic-param
#qvalue         =  ( "0" [ "." 0*3DIGIT ] )
#                  / ( "1" [ "." 0*3("0") ] )
#generic-param  =  token [ EQUAL gen-value ]
#gen-value      =  token / host / quoted-string
qvalue = pp.Combine((pp.Literal('0') + pp.Optional(pp.Literal('.') +  pp.Optional(pp.Word(pp.nums, max=3)))) ^ (pp.Literal('1') + pp.Optional(pp.Literal('.') +  pp.Optional(pp.Word('0', max=3)))))
gen_value = token ^ host ^ quoted_string
generic_param = token + pp.Optional(EQUAL + gen_value)


#Accept-Encoding  =  "Accept-Encoding" HCOLON
#                     [ encoding *(COMMA encoding) ]
#encoding         =  codings *(SEMI accept-param)
#codings          =  content-coding / "*"
#content-coding   =  token


#Accept-Language  =  "Accept-Language" HCOLON
#                     [ language *(COMMA language) ]
#language         =  language-range *(SEMI accept-param)
#language-range   =  ( ( 1*8ALPHA *( "-" 1*8ALPHA ) ) / "*" )
#
#Alert-Info   =  "Alert-Info" HCOLON alert-param *(COMMA alert-param)
#alert-param  =  LAQUOT absoluteURI RAQUOT *( SEMI generic-param )


#Allow  =  "Allow" HCOLON [Method *(COMMA Method)]


#Authorization     =  "Authorization" HCOLON credentials
#credentials       =  ("Digest" LWS digest-response)
#                     / other-response
#digest-response   =  dig-resp *(COMMA dig-resp)
#dig-resp          =  username / realm / nonce / digest-uri
#                      / dresponse / algorithm / cnonce
#                      / opaque / message-qop
#                      / nonce-count / auth-param
#username          =  "username" EQUAL username-value
#username-value    =  quoted-string
#digest-uri        =  "uri" EQUAL LDQUOT digest-uri-value RDQUOT
#digest-uri-value  =  rquest-uri ; Equal to request-uri as specified
#                     by HTTP/1.1
#message-qop       =  "qop" EQUAL qop-value
#cnonce            =  "cnonce" EQUAL cnonce-value
#cnonce-value      =  nonce-value
#nonce-count       =  "nc" EQUAL nc-value
#nc-value          =  8LHEX
#dresponse         =  "response" EQUAL request-digest
#request-digest    =  LDQUOT 32LHEX RDQUOT
#auth-param        =  auth-param-name EQUAL
#                     ( token / quoted-string )
#auth-param-name   =  token
#other-response    =  auth-scheme LWS auth-param
#                     *(COMMA auth-param)
auth_param = token + pp.Suppress(EQUAL) + (token ^ quoted_string)
Authorization = Parser(token + pp.Suppress(LWS) + auth_param + pp.ZeroOrMore(pp.Suppress(COMMA) + auth_param))
AuthorizationArgs = ('scheme', 'params')
AuthorizationQuotedparams = ('username', 'realm', 'nonce', 'uri', 'response', 'cnonce', 'opaque')
AuthorizationUnquotedparams = ('algorithm', 'qop', 'nc')
def AuthorizationParse(headervalue):
    res = Authorization.parse(headervalue)
    scheme = res.pop(0)
    params = ParameterDict()
    while res:
        k = res.pop(0)
        v = res.pop(0).strip()
        if scheme.lower()=='digest':
            if k.lower() in AuthorizationQuotedparams:
                if not (v.startswith('"') and v.endswith('"')):
                    raise Exception("quotes expected around {} value".format(k))
                if k.lower() == 'uri':
                    v = URI(v[1:-1])
                elif k.lower() == 'response':
                    v = v[1:-1]
                    if v: # Empty response are often seen but should not. BNF says: 32LHEX
                        try:
                            v = pp.Word(LHEX, exact=32).parseString(v)[0]
                        except:
                            raise Exception("32 lowercase hexa digits expected in response")
                else:
                    v = unquote(v)
            elif k.lower() in AuthorizationUnquotedparams:
                if v.startswith('"') or v.endswith('"'):
                    raise Exception("unexpected quotes around {} value".format(k))
                if k.lower() == 'nc':
                    v = int(pp.Word(LHEX, exact=8).parseString(v)[0], 16)
        else:
            v = unquote(v)
        params[k] = v
    return dict(scheme=scheme, params=params)
def AuthorizationDisplay(authorization):
    if authorization.scheme.lower() == 'digest':
        params = []
        for k,v in authorization.params.items():
            if v is None: continue
            if k.lower() in AuthorizationQuotedparams:
                v = quote(str(v), True)
            elif k.lower() == 'nc':
                v = "{:08x}".format(v)
            elif k.lower() not in AuthorizationUnquotedparams:
                v = quote(v)
            params.append("{}={}".format(k,v))
    else:
        params = ("{}={}".format(k,quote(v)) for k,v in authorization.params.items())
    return "{} {}".format(authorization.scheme, ','.join(params))

#Authentication-Info  =  "Authentication-Info" HCOLON ainfo
#                        *(COMMA ainfo)
#ainfo                =  nextnonce / message-qop
#                         / response-auth / cnonce
#                         / nonce-count
#nextnonce            =  "nextnonce" EQUAL nonce-value
#response-auth        =  "rspauth" EQUAL response-digest
#response-digest      =  LDQUOT *LHEX RDQUOT
nextnonce = pp.Literal('nextnonce') + pp.Suppress(EQUAL) + quoted_string
message_qop = pp.Literal('qop') + pp.Suppress(EQUAL) + token
response_auth = pp.Literal('rspauth') + pp.Suppress(EQUAL) + pp.Suppress(LDQUOT) + pp.Optional(pp.Word(LHEX),'') + pp.Suppress(RDQUOT)
cnonce = pp.Literal('cnonce') + pp.Suppress(EQUAL) + quoted_string
nonce_count = pp.Literal('nc') + pp.Suppress(EQUAL) + pp.Word(LHEX, exact=8)
ainfo = pp.Group(nextnonce ^ message_qop ^ response_auth ^ cnonce ^ nonce_count)
Authentication_Info = Parser(ainfo + pp.ZeroOrMore(pp.Suppress(COMMA) + ainfo))
Authentication_InfoArgs = ('params',)
def Authentication_InfoParse(headervalue):
    for k,v in Authentication_Info.parse(headervalue):
        yield dict(params={k:v})
def Authentication_InfoDisplay(auth):
    print(auth.params)
    return ",".join(("{}={}".format(k,v) for k,v in auth.params.items()))
Authentication_InfoMultiple = True

#Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
#callid   =  word [ "@" word ]
callid = pp.Combine(word + pp.Optional(pp.Literal('@') + word))
Call_ID = Parser(callid)
Call_IDAlias = 'i'
Call_IDArgs = ('callid',)
def Call_IDParse(headervalue):
    res = Call_ID.parse(headervalue)
    callid = res.pop(0)
    return dict(callid=callid)
def Call_IDDisplay(ci):
    return str(ci.callid)


#Call-Info   =  "Call-Info" HCOLON info *(COMMA info)
#info        =  LAQUOT absoluteURI RAQUOT *( SEMI info-param)
#info-param  =  ( "purpose" EQUAL ( "icon" / "info"
#               / "card" / token ) ) / generic-param


#Contact        =  ("Contact" / "m" ) HCOLON
#                  ( STAR / (contact-param *(COMMA contact-param)))
#contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
#name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
#addr-spec      =  SIP-URI / SIPS-URI / absoluteURI !!! identical to Request-URI
#display-name   =  *(token LWS)/ quoted-string
#
#contact-params     =  c-p-q / c-p-expires
#                      / contact-extension
#c-p-q              =  "q" EQUAL qvalue
#c-p-expires        =  "expires" EQUAL delta-seconds
#contact-extension  =  generic-param
#delta-seconds      =  1*DIGIT
addr_spec = pp.Group(SIP_URI ^ SIPS_URI ^ absoluteURI)
tokenLWS = pp.Word(pp.alphanums + '-.!%*_+`\'~ \t')
display_name = pp.Combine(tokenLWS) ^ quoted_string
name_addr = pp.Optional(display_name, '') + pp.Suppress(LAQUOT) + addr_spec + pp.Suppress(RAQUOT)
c_p_q = pp.CaselessLiteral('q') + EQUAL + qvalue
delta_seconds =  pp.Word(pp.nums, min=1)
c_p_expires = pp.CaselessLiteral('expires') + EQUAL + delta_seconds
contact_params = c_p_q ^ c_p_expires  ^ generic_param
contact_param = pp.Group(name_addr ^ addr_spec) + pp.Group(pp.ZeroOrMore(pp.Suppress(SEMI) + contact_params))

Contact = Parser(STAR ^ (pp.Group(contact_param) + pp.ZeroOrMore(pp.Group(pp.Suppress(COMMA) + contact_param))))
ContactAlias = 'm'
ContactArgs = ('display', 'address', 'params')
def ContactParse(headervalue):
    res = Contact.parse(headervalue)
    if res[0] == '*':
        yield dict(display=None, address='*', params={})
        return
    for addr,par in res:
        if len(addr) == 2:
            disp = unquote(addr.pop(0))
        else:
            disp = None
        addr = URI(addr.pop(0))
        params = {}
        while par:
            k = par.pop(0)
            if par and par[0] == '=':
                par.pop(0)
                v = unquote(par.pop(0))
                params[k] = v
            else:
                params[k] = None
        yield dict(display=disp, address=addr, params=params)
ContactMultiple = True
def ContactDisplay(contact):
    if contact.address == '*':
        return "*"
    if contact.display:
        addr = "{} <{}>".format(quote(contact.display), contact.address)
    elif contact.params or contact.address.params:
        addr = "<{}>".format(contact.address)
    else:
        addr = str(contact.address)
    params = (";{}{}".format(k, "={}".format(quote(v)) if v is not None else "") for k,v in contact.params.items())
    return "{}{}".format(addr, ''.join(params))


#Content-Disposition   =  "Content-Disposition" HCOLON
#                         disp-type *( SEMI disp-param )
#disp-type             =  "render" / "session" / "icon" / "alert"
#                         / disp-extension-token
#disp-param            =  handling-param / generic-param
#handling-param        =  "handling" EQUAL
#                         ( "optional" / "required"
#                         / other-handling )
#other-handling        =  token
#disp-extension-token  =  token


#Content-Encoding  =  ( "Content-Encoding" / "e" ) HCOLON
#                     content-coding *(COMMA content-coding)
#
#Content-Language  =  "Content-Language" HCOLON
#                     language-tag *(COMMA language-tag)
#language-tag      =  primary-tag *( "-" subtag )
#primary-tag       =  1*8ALPHA
#subtag            =  1*8ALPHA


#Content-Length  =  ( "Content-Length" / "l" ) HCOLON 1*DIGIT
Content_Length = Parser(pp.Word(pp.nums))
Content_LengthAlias = 'l'
Content_LengthArgs = ('length',)
def Content_LengthParse(headervalue):
    return dict(length=int(Content_Length.parse(headervalue)[0]))
def Content_LengthDisplay(cl):
    return str(cl.length)


#Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
#media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
#m-type           =  discrete-type / composite-type
#discrete-type    =  "text" / "image" / "audio" / "video"
#                    / "application" / extension-token
#composite-type   =  "message" / "multipart" / extension-token
#extension-token  =  ietf-token / x-token
#ietf-token       =  token
#x-token          =  "x-" token
#m-subtype        =  extension-token / iana-token
#iana-token       =  token
#m-parameter      =  m-attribute EQUAL m-value
#m-attribute      =  token
#m-value          =  token / quoted-string
m_parameter = token + pp.Suppress(EQUAL) + (token ^ quoted_string)
m_subtype = token
m_type = token
Content_Type = Parser(m_type + pp.Suppress(SLASH) + m_subtype + pp.ZeroOrMore(pp.Suppress(SEMI) + m_parameter))
Content_TypeAlias = 'c'
Content_TypeArgs = ('type', 'subtype', 'params')
def Content_TypeParse(headervalue):
    res = Content_Type.parse(headervalue)
    type = res.pop(0)
    subtype = res.pop(0)
    params = {}
    while res:
        k = res.pop(0)
        v = unquote(res.pop(0))
        params[k] = v
    return dict(type=type, subtype=subtype, params=params)
def Content_TypeDisplay(ct):
    params = (";{}={}".format(k, quote(v)) for k,v in ct.params.items())
    return "{}/{}{}".format(ct.type, ct.subtype, ''.join(params))


#CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
CSeq = Parser(pp.Word(pp.nums) + pp.Suppress(LWS) + Method)
CSeqArgs = ('seq', 'method')
def CSeqParse(headervalue):
    res = CSeq.parse(headervalue)
    seq = int(res.pop(0))
    method = res.pop(0)
    return dict(seq=seq, method=method)
def CSeqDisplay(cseq):
    return "{} {}".format(cseq.seq, cseq.method)

#Date          =  "Date" HCOLON SIP-date
#SIP-date      =  rfc1123-date
#rfc1123-date  =  wkday "," SP date1 SP time SP "GMT"
#date1         =  2DIGIT SP month SP 4DIGIT
#                 ; day month year (e.g., 02 Jun 1982)
#time          =  2DIGIT ":" 2DIGIT ":" 2DIGIT
#                 ; 00:00:00 - 23:59:59
#wkday         =  "Mon" / "Tue" / "Wed"
#                 / "Thu" / "Fri" / "Sat" / "Sun"
#month         =  "Jan" / "Feb" / "Mar" / "Apr"
#                 / "May" / "Jun" / "Jul" / "Aug"
#                 / "Sep" / "Oct" / "Nov" / "Dec"
#
#Error-Info  =  "Error-Info" HCOLON error-uri *(COMMA error-uri)
#error-uri   =  LAQUOT absoluteURI RAQUOT *( SEMI generic-param )
#
#Expires     =  "Expires" HCOLON delta-seconds
Expires = Parser(delta_seconds)
ExpiresArgs = ('delta',)
def ExpiresParse(headervalue):
    return dict(delta=int(Expires.parse(headervalue)[0]))
def ExpiresDisplay(e):
    return str(e.delta)

#From        =  ( "From" / "f" ) HCOLON from-spec
#from-spec   =  ( name-addr / addr-spec )
#               *( SEMI from-param )
#from-param  =  tag-param / generic-param
#tag-param   =  "tag" EQUAL token
tag_param = pp.CaselessLiteral('tag') + EQUAL + token
from_param = tag_param ^ generic_param
From = Parser(pp.Group(name_addr ^ addr_spec) + pp.Group(pp.ZeroOrMore(pp.Suppress(SEMI) + from_param)))
FromAlias = 'f'
FromArgs = ('display', 'address', 'params')
def FromParse(headervalue):
    addr,par = From.parse(headervalue)
    if len(addr) == 2:
        disp = unquote(addr.pop(0))
    else:
        disp = None
    addr = URI(addr.pop(0))
    params = {}
    while par:
        k = par.pop(0)
        if par and par[0] == '=':
            par.pop(0)
            v = unquote(par.pop(0))
            params[k] = v
        else:
            params[k] = None
    return dict(display=disp, address=addr, params=params)
FromDisplay = ContactDisplay


#In-Reply-To  =  "In-Reply-To" HCOLON callid *(COMMA callid)
#
#Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT
Max_Forwards = Parser(pp.Word(pp.nums))
Max_ForwardsArgs = ('max',)
def Max_ForwardsParse(headervalue):
    return dict(max=int(Max_Forwards.parse(headervalue)[0]))
def Max_ForwardsDisplay(mf):
    return str(mf.max)


#MIME-Version  =  "MIME-Version" HCOLON 1*DIGIT "." 1*DIGIT


#Min-Expires  =  "Min-Expires" HCOLON delta-seconds


#Organization  =  "Organization" HCOLON [TEXT-UTF8-TRIM]


#Priority        =  "Priority" HCOLON priority-value
#priority-value  =  "emergency" / "urgent" / "normal"
#                   / "non-urgent" / other-priority
#other-priority  =  token


#Proxy-Authenticate  =  "Proxy-Authenticate" HCOLON challenge
#challenge           =  ("Digest" LWS digest-cln *(COMMA digest-cln))
#                       / other-challenge
#other-challenge     =  auth-scheme LWS auth-param
#                       *(COMMA auth-param)
#digest-cln          =  realm / domain / nonce
#                        / opaque / stale / algorithm
#                        / qop-options / auth-param
#realm               =  "realm" EQUAL realm-value
#realm-value         =  quoted-string
#domain              =  "domain" EQUAL LDQUOT URI
#                       *( 1*SP URI ) RDQUOT
#URI                 =  absoluteURI / abs-path
#nonce               =  "nonce" EQUAL nonce-value
#nonce-value         =  quoted-string
#opaque              =  "opaque" EQUAL quoted-string
#stale               =  "stale" EQUAL ( "true" / "false" )
#algorithm           =  "algorithm" EQUAL ( "MD5" / "MD5-sess"
#                       / token )
#qop-options         =  "qop" EQUAL LDQUOT qop-value
#                       *("," qop-value) RDQUOT
#qop-value           =  "auth" / "auth-int" / token
Proxy_Authenticate = Parser(token + pp.Suppress(LWS) + auth_param + pp.ZeroOrMore(pp.Suppress(COMMA) + auth_param))
Proxy_AuthenticateArgs = AuthorizationArgs
def Proxy_AuthenticateParse(headervalue):
    res = Proxy_Authenticate.parse(headervalue)
    scheme = res.pop(0)
    params = ParameterDict()
    while res:
        k = res.pop(0)
        v = res.pop(0).strip()
        if scheme.lower()=='digest':
            if k.lower() in ('realm', 'domain', 'nonce', 'opaque', 'qop'):
                if not (v.startswith('"') and v.endswith('"')):
                    raise Exception("quotes expected around {} value".format(k))
                if k.lower() == 'domain':
                    v = URI(v[1:-1]) # TODO - should be a whitespace separated list of URI 
                else:
                    v = unquote(v)
            elif k.lower() in ('algorithm', 'stale'):
                if k.lower() == 'stale':
                    if v.lower() not in ('true', 'false'):
                        raise Exception("stale value should be 'true' or 'false'")
        else:
            v = unquote(v)
        params[k] = v
    return dict(scheme=scheme, params=params)
def Proxy_AuthenticateDisplay(authenticate):
    if authenticate.scheme.lower() == 'digest':
        params = ("{}={}".format(k,quote(str(v),True) if k.lower() not in ('algorithm','stale') else v) for k,v in authenticate.params.items())
    else:
        params = ("{}={}".format(k,quote(v)) for k,v in authenticate.params.items())
    return "{} {}".format(authenticate.scheme, ','.join(params))


#Proxy-Authorization  =  "Proxy-Authorization" HCOLON credentials
Proxy_AuthorizationArgs = AuthorizationArgs
Proxy_AuthorizationParse = AuthorizationParse
Proxy_AuthorizationDisplay = AuthorizationDisplay


#Proxy-Require  =  "Proxy-Require" HCOLON option-tag
#                  *(COMMA option-tag)
#option-tag     =  token
#
#Record-Route  =  "Record-Route" HCOLON rec-route *(COMMA rec-route)
#rec-route     =  name-addr *( SEMI rr-param )
#rr-param      =  generic-param
#
#Reply-To      =  "Reply-To" HCOLON rplyto-spec
#rplyto-spec   =  ( name-addr / addr-spec )
#                 *( SEMI rplyto-param )
#rplyto-param  =  generic-param
#Require       =  "Require" HCOLON option-tag *(COMMA option-tag)
#
#Retry-After  =  "Retry-After" HCOLON delta-seconds
#                [ comment ] *( SEMI retry-param )
#
#retry-param  =  ("duration" EQUAL delta-seconds)
#                / generic-param
#
#Route        =  "Route" HCOLON route-param *(COMMA route-param)
#route-param  =  name-addr *( SEMI rr-param )
rr_param = generic_param
route_param = name_addr + pp.ZeroOrMore(pp.Suppress(SEMI) + rr_param)

Route = Parser(pp.Group(route_param) + pp.ZeroOrMore(pp.Group(pp.Suppress(COMMA) + route_param)))
RouteArgs = ('display', 'address', 'params')
def RouteParse(headervalue):
    for res in Route.parse(headervalue):
        disp = res.pop(0)
        addr = URI(res.pop(0))
        params = {}
        while res:
            k = res.pop(0)
            if res and res[0] == '=':
                res.pop(0)
                params[k] = res.pop(0)
            else:
                params[k] = None
        yield dict(display=disp, address=addr, params=params)
RouteMultiple = True
RouteDisplay = ContactDisplay


#Server           =  "Server" HCOLON server-val *(LWS server-val)
#server-val       =  product / comment
#product          =  token [SLASH product-version]
#product-version  =  token


#Subject  =  ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]


#Supported  =  ( "Supported" / "k" ) HCOLON
#              [option-tag *(COMMA option-tag)]


#Timestamp  =  "Timestamp" HCOLON 1*(DIGIT)
#               [ "." *(DIGIT) ] [ LWS delay ]
#delay      =  *(DIGIT) [ "." *(DIGIT) ]


#To        =  ( "To" / "t" ) HCOLON ( name-addr
#             / addr-spec ) *( SEMI to-param )
#to-param  =  tag-param / generic-param
ToAlias = 't'
ToArgs = FromArgs
ToParse = FromParse
ToDisplay = FromDisplay


#Unsupported  =  "Unsupported" HCOLON option-tag *(COMMA option-tag)
#User-Agent  =  "User-Agent" HCOLON server-val *(LWS server-val)

#Via               =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
#via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
#via-params        =  via-ttl / via-maddr
#                     / via-received / via-branch
#                     / via-extension
#via-ttl           =  "ttl" EQUAL ttl
#via-maddr         =  "maddr" EQUAL host
#via-received      =  "received" EQUAL (IPv4address / IPv6address)
#via-branch        =  "branch" EQUAL token
#via-extension     =  generic-param
#sent-protocol     =  protocol-name SLASH protocol-version
#                     SLASH transport
#protocol-name     =  "SIP" / token
#protocol-version  =  token
#transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
#                     / other-transport
#sent-by           =  host [ COLON port ]
#ttl               =  1*3DIGIT ; 0 to 255
via_extension = generic_param
via_branch = pp.CaselessLiteral('branch') + EQUAL + token
via_received = pp.CaselessLiteral('received') + EQUAL + (IPv4address ^ IPv6address)
via_maddr = pp.CaselessLiteral('maddr') + EQUAL + host
ttl = pp.Word(pp.nums, max=3)
via_ttl = pp.CaselessLiteral('ttl') + EQUAL + ttl
via_params = via_ttl ^ via_maddr ^ via_received ^ via_branch ^ via_extension
sent_by = host + pp.Optional(pp.Suppress(COLON) + pp.Word(pp.nums), None)
transport = pp.CaselessLiteral('UDP') ^ pp.CaselessLiteral('TCP') ^ pp.CaselessLiteral('TLS') ^ pp.CaselessLiteral('SCTP') ^ other_transport
protocol_version = token
protocol_name = pp.CaselessLiteral('SIP') ^ token
sent_protocol = pp.Combine(protocol_name + SLASH + protocol_version + SLASH + transport)
via_parm = sent_protocol + pp.Suppress(LWS) + sent_by + pp.ZeroOrMore(SEMI + via_params)

Via = Parser(pp.Optional(pp.Group(via_parm) + pp.ZeroOrMore(pp.Group(COMMA + via_parm))))
ViaAlias = 'v'
ViaArgs = ('protocol', 'host', 'port', 'params')
def ViaParse(headervalue):
    for res in Via.parse(headervalue):
        protocol = res.pop(0)
        host = res.pop(0)
        port = res.pop(0)
        if port is not None:
            port = int(port)
        params = {}
        while res:
            k = res.pop(0)
            if res and res[0] == '=':
                res.pop(0)
                params[k] = res.pop(0)
            else:
                params[k] = None
        yield dict(protocol=protocol, host=host, port=port, params=params)
ViaMultiple = True
def ViaDisplay(via):
    params = (";{}{}".format(k, ("={}".format(v) if v is not None else "") or "") for k,v in via.params.items())
    if via.port:
        hostport = "{}:{}".format(via.host, via.port)
    else:
        hostport = via.host
    return "{} {}{}".format(via.protocol, hostport, ''.join(params))

#
#Warning        =  "Warning" HCOLON warning-value *(COMMA warning-value)
#warning-value  =  warn-code SP warn-agent SP warn-text
#warn-code      =  3DIGIT
#warn-agent     =  hostport / pseudonym
#                  ;  the name or pseudonym of the server adding
#                  ;  the Warning header, for use in debugging
#warn-text      =  quoted-string
#pseudonym      =  token


#WWW-Authenticate  =  "WWW-Authenticate" HCOLON challenge
WWW_AuthenticateArgs = Proxy_AuthenticateArgs
WWW_AuthenticateParse = Proxy_AuthenticateParse
WWW_AuthenticateDisplay = Proxy_AuthenticateDisplay


#extension-header  =  header-name HCOLON header-value
#header-name       =  token
#header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
#message-body  =  *OCTET
