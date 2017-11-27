#! /usr/bin/python3
# coding: utf-8

import logging
log = logging.getLogger('Dialog')


def Dialog(request, addr):
    return None
    dialog = match(request)
    if dialog:
        return dialog
    if isinstance(request, Message.INVITE):
        return InviteDialog(request, addr)
#        if isinstance(request, Message.SUBSCRIBE):
#            return SubscribeDialog(request, addr)
    return None

def match(request, addr):
    pass

def init():
    pass
    
#class InviteDialog(Dialog):
##    def __init__(self, request, addr):
##        A.__init__(self, request, addr)
#    
#    def terminate(self):
#        BYE or CANCEL
#    def reinvite(self):
#        pass
    
        

