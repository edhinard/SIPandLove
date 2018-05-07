import sys
import logging
import types

assert sys.version_info >= (3,5)

def getIndentedMessage(record):
    return logging.LogRecord.getMessage(record).replace('\n','\n   ')
class ColoredFormatter(logging.Formatter):
    escapecodes = {'CRITICAL':'2;91;41',
                   'ERROR':'2;91',
                   'WARNING':'22;93',
                   'INFO':'2;96',
                   'DEBUG':'2;94'
                   }
    def __init__(self):
        logging.Formatter.__init__(self, "\x1b[2;37m%(asctime)s %(coloredlevelname)s \x1b[1;97m%(name)s\x1b[m %(message)s")
    def format(self, record):
        record.coloredlevelname = "\x1b[{}m{:<8}\x1b[m".format(ColoredFormatter.escapecodes[record.levelname], record.levelname)
        record.getMessage = types.MethodType(getIndentedMessage, record)
        return logging.Formatter.format(self, record)

loghandler = logging.StreamHandler(sys.stdout)
logformatter = ColoredFormatter()
logformatter.default_time_format = "%H:%M:%S"
loghandler.setFormatter(logformatter)
loggers = {mod:logging.getLogger(mod) for mod in ('Header', 'Message', 'Transport', 'Security', 'Transaction', 'Media', 'Dialog', 'UA', 'Main')}
for log in loggers.values():
    log.setLevel('WARNING')
    log.addHandler(loghandler)
log = logging.getLogger('Main')

from .SIPBNF import URI
from .Message import SIPMessage,SIPResponse,SIPRequest,REGISTER,INVITE,ACK,BYE,CANCEL,OPTIONS
from .UA import SIPPhoneClass
from .Media import Media
