#! /usr/bin/python3
# coding: utf-8

import multiprocessing
import threading
import time

def arm(duration, cb, *args, **kwargs):
    MANAGER.arm(duration, cb, *args, **kwargs)
    
class TimerManager(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        self.lock = threading.Lock()
        self.timers = {}
        self.pipe,childpipe = multiprocessing.Pipe()
        self.process = multiprocessing.Process(target=TimerManager.processloop, args=(childpipe,), daemon=True)
        self.process.start()
        self.start()

    def arm(self, duration, cb, *args, **kwargs):
        timer = (cb, args, kwargs)
        idt = id(timer)
        with self.lock:
            self.timers[idt] = timer
        self.pipe.send((duration, idt))

    # Thread loop
    def run(self):
        while True:
            idt = self.pipe.recv()
            with self.lock:
                cb,args,kwargs = self.timers.pop(idt)
            cb(*args, **kwargs)

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
            
        
MANAGER = TimerManager()
