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
        
    async def register(self):
        reg = Message.REGISTER(self.sipuri)
        m = await Transaction.manager.send(reg)
        if m.code in (401, 407):
            reg.authenticate(m.headers.wwwauth, self.password)
            m = await Transaction.manager.send(reg)
        if m.code == 200:
            return 'OK'
    
    async def invite(self, to, sdp, audioin, audioout):
        inv = Message.INVITE()
        m = await Transaction.manager.send(reg)
        if m.code in (401, 407):
            reg.authenticate(m.headers.wwwauth, password)
            m = await Transaction.manager.send(reg)
        if m.code == 200:
            return 'OK'

