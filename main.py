#! /usr/bin/python3
# coding: utf-8

import sys
import asyncio
import User

usercreds = (
    ('u1', 'pass1'),
    
    ('u2', 'pass2'),
    ('u3', 'pass3'),
    ('u4', 'pass4'),
)
         
loop = asyncio.get_event_loop()
users = loop.run_until_complete(asyncio.gather(*[User.User(*u).register() for u in usercreds], return_exceptions=True))

errors = [u for u in users if isinstance(u, Exception)]
if errors:
    for e in errors:
        print(e)
    sys.exit()

u0 = users[0]
loop.run_until_complete(asyncio.gather(*[u0.invite(u) for u in users[1:]]))
