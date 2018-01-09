#! /usr/bin/python3
# coding: utf-8

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
    def __init__(self, local, remote):
        self.callid = local.callid
        self.localtag = local.fromtag if isinstance(local, Message.SIPRequest) else local.totag
        self.remotetag = remote.fromtag if isinstance(remote, Message.SIPRequest) else remote.totag
        self.localtarget = local.getheader('contact').address
        self.remotetarget = remote.getheader('contact').address
        self.localseq = local.seq
        self.remoteseq = remote.seq
    @property
    def ident(self):
        return "{}/{}/{}".format(self.callid, self.localtag, self.remotetag)
