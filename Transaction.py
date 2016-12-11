#! /usr/bin/python3
# coding: utf-8

import sys
import asyncio
import time

import Message
import Transport

class TransactionManager:
    def __init__(self, transport):
        self.transport = transport
    def run(self):
        loop = asyncio.get_event_loop()
        loop.add_reader(self.transport.pipe.fileno(), self.gotmessage)
        loop.run_forever()
    def gotmessage(self):
        print(self.transport.recv())
        

class Transaction:
    def __init__(self, branch, method):
        self.branch = branch
        self.method = method

        
class ClientTransaction(Transaction):
    def __init__(self, branch, method):
        self.id = (branch, method)
        Transaction.__init__(self, branch, method)
    

class ServerTransaction(Transaction):
    def __init__(self, branch, method, sentby):
        self.id = (branch, method, sentby)
        Transaction.__init__(self, branch, method)

    
t = Transport.Transport('x')
m = TransactionManager(t)
m.run()
