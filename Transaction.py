#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import time

import Message
import Transport

class TransactionManager:
    def __init__(self, transport):
        self.transport = transport
        self.clienttransactions = {}
        self.servertransactions = {}
        
    def messagereceived(self):
        message = self.transport.recv()
        
        if isinstance(message, Message.SIPRequest):
            id = ServerTransaction.id(message)
            self.servertransactions[id] = ServerTransaction(message)


            if not id in self.servertransactions:
                self.servertransactions[id] = ServerTransaction(message)
            transaction = self.servertransactions[id]

        if isinstance(message, Message.SIPResponse):
            id = ClientTransaction.id(message)


            
    def send(self, message):
        transaction = ClientTransaction(message.headers, message.method)

class Transaction(threading.Thread):
    def __init__(self, branch, method):
        threading.Thread.__init__(self)
        self.branch = branch
        self.method = method

        self.start()

    def run(self):
        while True:
            
        
class ClientTransaction(Transaction):
    def __init__(self, branch, method):
        self.id = (branch, method)
        Transaction.__init__(self, branch, method)
    

class ServerTransaction(Transaction):
    @staticmethod
    def id(request):
        return (request.branch, request.method, request.sentby)
    
    def __init__(self, request):
        self.id = (branch, method, sentby)
        Transaction.__init__(self, branch, method)

    
t = Transport.Transport('x')
manager = TransactionManager(t)
loop = asyncio.get_event_loop()
loop.add_reader(t.transport.pipe.fileno(), t.messagereceived)
