#! /usr/bin/python3
# coding: utf-8

import sys
import asyncio
import time

import Message
import Transport
import Transaction
import User

transport = Transport.Transport('x')
manager = Transaction.TransactionManager(transport)

users = (
    ('u1', 'pass1'),
    ('u2', 'pass2'),
    ('u3', 'pass3'),
    ('u4', 'pass4'),
)
         
loop = asyncio.get_event_loop()

registers = asyncio.gather(*[User.User(*u).register() for u in users])
loop.run_until_complete(registers)

u0 = User.users[0]
invites =asyncio.gather(*[u0.invite(u) for u in Users.users[1:]])
loop.run_until_complete(invites)
