#! /usr/bin/python3
# coding: utf-8

import sys

import Message
import Transaction

class User:
    users = {}
    
    def __init__(self, sipuri, password=None, invitecb=None):
        if sipuri in User.users:
            raise RuntimeError("Duplicate User: {}".format(sipuri))
        self.sipuri = sipuri
        self.password = password
        self.invitecb = invitecb
        self.registered = False
        self.registering = None
        User.users[self.sipuri] = self

    def __del__(self):
        del User.users[self.sipuri]
        
    def register(self, cb=):
        if self.registering:
            raise RuntimeError("Already registering")
        reg = Message.REGISTER(self.sipuri)
        self.registering = UA.UAC(reg, cb=self._registercb)

    def _registercb(self, result):
        self.registering = None
        
    def invite(self, to, sdp, audioin, audioout):
        inv = Message.INVITE()
        self.invitations.append(UA.UAC(inv, self))

        
