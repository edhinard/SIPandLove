#! /usr/bin/python3
# coding: utf-8

import sys
import User

usercreds = (
    ('u1', 'pass1'),
    
    ('u2', 'pass2'),
    ('u3', 'pass3'),
    ('u4', 'pass4'),
)
users = [User.User(*u, register=True) for u in usercreds]     
for u in users:
    try:
        u.wait_registered()
    except Exception as e:
        print(e)

u0 = users[0]
for u in users[1:]:
    try:
        u.invite(u0)
    except Exception as e:
        print(e)

