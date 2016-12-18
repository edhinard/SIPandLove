#! /usr/bin/python3
# coding: utf-8

#import asyncio
#
#@asyncio.coroutine
#def toto():
#    print('a')
#    yield from asyncio.sleep(2)
#    print('b')
#
#loop = asyncio.get_event_loop()
##loop.create_task(toto())
#asyncio.ensure_future(toto())
#try:
#    loop.run_forever()
#finally:
#    loop.close()
#

import threading
import time

class T(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.count = 0
        #self.finished = Event()
        
    def run(self):
        while True:
            print(self.name, self.count)
            self.count += 1
            #time.sleep(1)

ts = [T() for i in range(10)]
[t.start() for t in ts]
[t.join() for t in ts]
