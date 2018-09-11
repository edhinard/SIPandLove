import sys
import logging
import types
import re

assert sys.version_info >= (3,5)

class Logger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)
    def logandraise(self, exception):
        self.error(str(exception))
        exception.logged = True
        raise exception from None
logging.setLoggerClass(Logger)

def excepthook(type, value, traceback):
    if getattr(value, 'logged', False):
        return
#    log.error(str(value))
    sys.__excepthook__(type, value, traceback)
sys.excepthook = excepthook

class ColoredFormatter(logging.Formatter):
    STATUS_LINE_RE = re.compile('SIP/2.0 (?P<code>[1-7]\d\d) (?P<reason>.+)', re.IGNORECASE)
    REQUEST_LINE_RE = re.compile('''(?P<method>[A-Za-z0-9.!%*_+`'~-]+) (?P<requesturi>[^ ]+) SIP/2.0''', re.IGNORECASE)
    default_time_format = "%H:%M:%S"
    escapecodes = {'CRITICAL':('2;91;41','97'),
                   'ERROR':('2;91','2;91'),
                   'WARNING':('22;93','97'),
                   'INFO':('2;96','97'),
                   'DEBUG':('2;94','97')
                   }
    def format(self, record):
        record.indentedmessage = self.indentmessage(logging.LogRecord.getMessage(record))
        record.color1,record.color2 = ColoredFormatter.escapecodes[record.levelname]
        return logging.Formatter.format(self, record)
    def indentmessage(self, message):
        lines = message.splitlines()
        if len(lines) > 1:
            lines[0] += '\x1b[m'
        if len(lines) > 2:
            requestline = ColoredFormatter.REQUEST_LINE_RE.search(lines[1])
            statusline = ColoredFormatter.STATUS_LINE_RE.search(lines[1])
            if requestline:
                lines[1] = "\x1b[92m{method} {requesturi}\x1b[m SIP/2.0".format(**requestline.groupdict())
            elif statusline:
                lines[1] = "\x1b[mSIP/2.0 \x1b[92m{code} {reason}\x1b[m".format(**statusline.groupdict())
        return '\n   '.join(lines)


# Module Internal loggers
loghandler = logging.StreamHandler(sys.stdout)
logformatter = ColoredFormatter("\x1b[2;37m%(asctime)s \x1b[%(color1)sm%(levelname)-8s\x1b[m \x1b[4m%(name)s\x1b[m \x1b[%(color2)sm%(indentedmessage)s\x1b[m")
loghandler.setFormatter(logformatter)
loggers = {}
for submodule,level in (('Header',      'WARNING'),
                        ('Message',     'WARNING'),
                        ('Security',    'WARNING'),
                        ('Transaction', 'WARNING'),
                        ('Media',       'WARNING'),
                        ('MSRP',        'WARNING'),
                        ('Dialog',      'INFO'),
                        ('Transport',   'INFO'),
                        ('UA',          'INFO')):
    log = logging.getLogger(submodule)
    log.setLevel(level)
    log.addHandler(loghandler)
    loggers[submodule] = log


# Script logger
mainloghandler = logging.StreamHandler(sys.stdout)
mainlogformatter = ColoredFormatter("\x1b[2;37m%(asctime)s \x1b[%(color1)sm%(indentedmessage)s\x1b[m")
mainloghandler.setFormatter(mainlogformatter)
log = logging.getLogger('Main')
log.setLevel('INFO')
log.addHandler(mainloghandler)
log.error("{:#^66}".format("< SIPandLove >"))


from .SIPBNF import URI
from .Message import SIPMessage,SIPResponse,SIPRequest,REGISTER,INVITE,ACK,BYE,CANCEL,OPTIONS
from .Transport import Transport
from .UA import SIPPhoneClass
from .Media import Media
from .MSRP import MSRP
from .Pcap import Pcap
from . import Header
