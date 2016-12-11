#! /usr/bin/python3
# coding: utf-8

import asyncio

@asyncio.coroutine
def toto():
    print('a')
    yield from asyncio.sleep(2)
    print('b')

loop = asyncio.get_event_loop()
#loop.create_task(toto())
asyncio.ensure_future(toto())
try:
    loop.run_forever()
finally:
    loop.close()
