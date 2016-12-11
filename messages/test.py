#! /usr/bin/python3
# coding: utf-8

import sys
import glob
import socket
sys.path.append('..')
import Message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
#sock.connect(('172.20.35.253', 5060))
sock.connect(('192.168.1.18', 5060))

for filename in glob.glob('*.txt'):
    with open(filename, 'rb') as f:
        m = f.read()
        print(filename)
        sock.send(m)
        try:
            buf = sock.recv(1024)
            m = Message.SIPMessage.frombytes(buf)
            if m:
                print(m)
            else:
                print(buf)
        except:
            raise
            print("<>")
        print('\n-------------------------\n')
