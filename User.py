#! /usr/bin/python3
# coding: utf-8

import sys
import asyncio

import Message
import Transaction

class User:
    def __init__(self, sipuri, password=None, invitecb=None):
        self.sipuri = sipuri
        self.password = password
        self.invitecb = invitecb
        self.registered = False
        
    async def register(self):
        reg = Message.REGISTER(self.sipuri)
        m = await Transaction.manager.send(reg)
        if m.code == 401:
            reg.authenticate(m.headers['WWW-Authenticate'], self.password)
            m = await Transaction.manager.send(reg)
        elif m.code == 407:
            reg.authenticate(m.headers['Proxy-Authenticate'], self.password)
            m = await Transaction.manager.send(reg)

        if m.code == 200:
            self.registered = True
            return self

        raise Exception(str(m))
        
    async def invite(self, to, sdp, audioin, audioout):
        inv = Message.INVITE()
        m = await Transaction.manager.send(reg)
        if m.code == 401:
            reg.authenticate(m.headers['WWW-Authenticate'], self.password)
            m = await Transaction.manager.send(reg)
        elif m.code == 407:
            reg.authenticate(m.headers['Proxy-Authenticate'], self.password)
            m = await Transaction.manager.send(reg)

        if m.code == 200:
            self.registered = True
            return self

        raise Exception(str(m))

