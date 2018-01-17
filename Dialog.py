#! /usr/bin/python3
# coding: utf-8

import random
import logging
log = logging.getLogger('Dialog')

from . import Message

def UACid(message):
    totag = message.totag
    if not totag:
        return None
    return "{}/{}/{}".format(message.callid, message.fromtag, totag)

def UASid(message):
    totag = message.totag
    if not totag:
        return None
    return "{}/{}/{}".format(message.callid, totag, message.fromtag)


class Dialog:
    def __init__(self, request, response, uac=False, uas=False):
        if (uac and uas) or (not uac and not uas):
            raise ValueError("uac xor uas must be True")
        if uac:
            self.callid       = request.callid
            self.localtag     = request.fromtag
            self.remotetag    = response.totag
            self.localtarget  = request.getheader('from').address
            self.remotetarget = request.getheader('to').address
            self.localseq     = request.seq
            self.remoteseq    = None
        if uas:
            self.callid = request.callid
            self.localtag = response.totag
            self.remotetag = request.fromtag
            self.localtarget = request.getheader('to').address
            self.remotetarget = request.getheader('from').address
            self.localseq = random.randint(0,0x7fff)
            self.remoteseq = request.seq
    @property
    def ident(self):
        return "{}/{}/{}".format(self.callid, self.localtag, self.remotetag)
