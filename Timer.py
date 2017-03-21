#! /usr/bin/python3
# coding: utf-8

import multiprocessing
import threading
import time

class SIPTimer:
    def __init__(self, transaction):
        self.transaction = transaction
        self.state = transaction.state
for name,duration in (
        ('T1',lambda self,T1,T2,T4:T1),
        ('T2',lambda self,T1,T2,T4:T2),
        ('T4',lambda self,T1,T2,T4:T4),
        ('A',lambda self,T1,T2,T4:T1),
        ('B',lambda self,T1,T2,T4:64*T1),
        ('C',lambda self,T1,T2,T4:180),
        ('D',lambda self,T1,T2,T4:32),
        ('E',lambda self,T1,T2,T4:T1),
        ('F',lambda self,T1,T2,T4:64*T1),
        ('G',lambda self,T1,T2,T4:T1),
        ('H',lambda self,T1,T2,T4:64*T1),
        ('I',lambda self,T1,T2,T4:T4),
        ('J',lambda self,T1,T2,T4:64*T1),
        ('K',lambda self,T1,T2,T4:T4),
        ('t200',lambda self,T1,T2,T4:.2)
):
    globals()[name] = type(name, (SIPTimer,), dict(duration=duration))
    
    
class TimerManager(threading.Thread):
    def __init__(self, T1=.5, T2=4., T4=5.):
        threading.Thread.__init__(self, daemon=True)
        self.T1 = T1
        self.T2 = T2
        self.T4 = T4
        self.lock = threading.Lock()
        self.timers = {}
        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = multiprocessing.Process(target=Timer.processloop, args=(childpipe,), daemon=True)
        self.process.start()
        self.start()

    def new(self, timer):
        # SIPTimer objects are not sent to the process through the pipe
        #  their id are sent instead
        # Execution context = Transaction state change == Timer thread (timerinput) or Transport thread through UA.ingress (messageinput)
        idt = id(timer)
        duration = timer.duration(self.T1, self.T2, self.T4)
        with self.lock:
            self.timers[idt] = timer
        self.pipe.send(duration, idt)

    # Thread loop
    def run(self):
        while True:
            idt = self.pipe.recv
            with self.lock:
                timer = self.timers.pop(idt)
            timer.transaction.timerinput(timer)

    # Process loop
    @staticmethod
    def processloop(pipe):
        sortedtimers = []
        while True:
            #
            # Fire all passed timers
            #
            currenttime = time.monotonic()
            while sortedtimers and currenttime >= sortedtimers[0][0]:
                targettime,idt = sortedtimers.pop(0)
                pipe.send(idt)

            #
            # Compute sleep duration
            #  = time of first timer - current time
            #
            if not sortedtimers:
                sleep = None
            else:
                sleep = sortedtimers[0][0] - currenttime

            #
            # Wait for a new timer demand coming from pipe (timeout=sleep)
            #  if there is one:
            #   convert duration to absolute time and place it in the sorted list of timers
            #
            if pipe.poll(sleep):
                duration,idt = pipe.recv()
                currenttime = time.monotonic()
                targettime = currenttime + duration
                sortedtimers.append((targettime, idt))
                sortedtimers.sort()
            
        
