#! /usr/bin/python3
# coding: utf-8

import sys
import threading
import time

import Message

class Transaction:
    def __init__(self, request, timers):
        self.statelock = threading.Lock()
        self._state = None
        self.request = request
        self.timers = timers
        self.semaphore = threading.Semaphore(0)
        self.resplock = threading.Lock()
        self.responses = []
        self.lastresponse = -1
        self.index = 0

    # Each state transition activate specific timers
    def getstate(self):
        return self._state
    def setstate(self, state):
        assert state in self.statesandtimers
        self._state = state
        for timerclass in self.statesandtimers[state]:
            self.timers.new(timerclass(self))
    state = property(getstate, setstate)
        
    def start(self):
        pass

    def messageinput(self, message):
        pass
            
    def response(self, response, last=False):
        with self.resplock:
            self.responses.append(response)
        if last:
            with self.resplock:
                self.lastresponse = len(self.responses)-1
        self.semaphore.release()
            
        
class ClientTransaction(Transaction):
    def __init__(self, request, timers):
        Transaction.__init__(self, request, timers)
    
    def responses(self):
        while True:
            self.semaphore.acquire()
            with self.resplock:
                resp = self.responses[self.index]
            yield resp
            with self.resplock:
                end = self.index == self.lastresponse
            if end:
                return
            self.index += 1

class INVITEclientTransaction(ClientTransaction):
    def __init__(self, request):
        ClientTransaction.__init__(self, request)
    def messageinput(self, message):
        pass
        
class NonINVITEclientTransaction(ClientTransaction):
    self.statesandtimers = {
        'Trying':(Timer.E, Timer.F),
        'Proceeding':(Timer.E, Timer.F),
        'Completed':(Timer.K,)
        'Terminated':()
        }
    
    def __init__(self, request):
        ClientTransaction.__init__(self, request)
    def start(self):
        self.state = 'Trying'
        self.request.send()

    def messageinput(self, message):
        # Execution context = Transport thread through UA.ingress
        assert isinstance(message, Message.SIPResponse)
        response = message
        
        with self.statelock:
            if self.state == 'Trying':
                if response.familycode  == 1:
                    self._addresponse(response)
                    self.state = 'Proceeding'

                elif response.familycode in (2,3,4,5,6):
                    self._addresponse(response, last=True)
                    self.state = 'Completed'

            elif self.state == 'Proceeding':
                if response.familycode  == 1:
                    self._addresponse(response)

                elif response.familycode in (2,3,4,5,6):
                    self._addresponse(response, last=True)
                    self.state = 'Completed'

            elif self.state == 'Completed':
                pass

            elif self.state == 'Terminated':
                pass
        
    def timerinput(self, timer):
        # Execution context = Timer thread
        assert isinstance(message, Timer.SIPTimer)        
        with self.statelock:
            if self.state != timer.state:
                return
            if self.state == 'Trying':
                if isinstance(timer, Timer.E):
                    self.request.send()
                elif isinstance(timer, Timer.F):
                    self._addresponse(timer, last=True)
                    self.state = 'Terminated'

            elif self.state == 'Proceeding':
                if isinstance(timer, Timer.E):
                    self.request.send()
                elif isinstance(timer, Timer.F):
                    self._addresponse(timer, last=True)
                    self.state = 'Terminated'

            elif self.state == 'Completed':
                if isinstance(timer, Timer.K):
                    self.state = 'Terminated'

            elif self.state == 'Terminated':
                pass
    
            
class ServerTransaction(Transaction):
    @staticmethod
    def id(request):
        return (request.branch, request.method, request.sentby)
    
    def __init__(self, request):
        Transaction.__init__(self, request)
        self.id = (branch, method, sentby)

    
