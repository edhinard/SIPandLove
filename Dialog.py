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
    def __init__(self, ua, local, remote):
        self.ua = ua
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


class Session(Dialog):
    def __init__(self, ua, local, remote, media):
        super().__init__(ua, local, remote)
        self.media = media
        log.info("%s created", self)

    def __str__(self):
        return "Session-{}".format(self.ident)
    
    def bye(self):
        if self.media is None:
            log.info("%s closing locally but allready closed", self)
            return
        log.info("%s closing locally", self)
        self.localseq += 1
        bye = Message.BYE(self.remotetarget,
                         'to:{};tag={}'.format(self.remotetarget, self.remotetag),
                         'from:{};tag={}'.format(self.localtarget, self.localtag),
                         'call-id:{}'.format(self.callid),
                         'cseq: {} BYE'.format(self.localseq))
        self.media.stop()
        self.media = None
        try:
            finalresponse = self.ua.sendmessageandwaitforresponse(bye)
        except Exception as e:
            log.info("%s closing failed: %s", self, e)
            return
        if finalresponse.familycode != 2:
            log.info("%s closing failed: %s %s", self, finalresponse.code, finalresponse.reason)
            return
        log.info("%s closing ok", self)

    def invitehandler(self, invite):
        pass
    
    def byehandler(self, bye):
        if self.media is None:
            log.info("%s closed by remote but allready closed", self)
            return bye.response(481)
        log.info("%s closed by remote", self)
        self.media.stop()
        self.media = None
        return bye.response(200)
