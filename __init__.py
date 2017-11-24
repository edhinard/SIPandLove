import sys
import logging

assert sys.version_info >= (3,5)

loghandler = logging.StreamHandler()
logformatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
logformatter.default_time_format = "%H:%M:%S"
loghandler.setFormatter(logformatter)
loggers = {mod:logging.getLogger(mod) for mod in ('Header', 'Message', 'Transport', 'Transaction', 'Media', 'UA')}
for log in loggers.values():
    log.setLevel('WARNING')
    log.addHandler(loghandler)


from .SIPBNF import URI
from .Message import SIPMessage,SIPResponse,SIPRequest,REGISTER,INVITE,ACK,BYE,CANCEL,OPTIONS
from .Transport import Transport
from .Transaction import TransactionManager
from .Media import Media, RTPFile, RTPStream, RTPRandomStream
from .UA import SIPPhone
