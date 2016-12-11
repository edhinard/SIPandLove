#! /usr/bin/python3
# coding: utf-8


class A:
    def __new__(cls, x):
        if x == 'b':
            return super().__new__(B)
        elif x == 'c':
            return super().__new__(C)
        else:
            return super().__new__(cls)
    def __init__(self, x):
        print("A.__init__", x)
        self.x = x

class B(A):
    pass
class C(A):
    pass


print(type(A('b')))
print(type(A('z')))
