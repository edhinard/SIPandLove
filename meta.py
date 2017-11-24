#! /usr/bin/python3
# coding: utf-8

def A(cl, i):
    if cl == 'b':
        if len(B.bs) > i:
            return B.bs[i]
        return B(cl, i)
    elif cl == 'c':
        if len(C.cs) > i:
            return C.cs[i]
        return C(cl, i)
    else:
        return None

class AA:
    def __init__(self, cl, i):
        print("AA.__init__", cl, i)
        self.cl = cl
        self.i = i

#class A:
#    def __new__(cls, cl, i):
#        if cl == 'b':
#            if len(B.bs) > i:
#                return B.bs[i]
#            return super().__new__(B)
#        elif cl == 'c':
#            if len(C.cs) > i:
#                return C.cs[i]
#            return super().__new__(C)
#        else:
#            return None
#    def __init__(self, cl, i):
#        print("A.__init__", cl, i)
#        self.cl = cl
#        self.i = i

class B(AA):
    bs = []
    def __init__(self, cl, i):
        AA.__init__(self, cl, i)
        print("B.__init__", cl, i)
        B.bs.append(self)

class C(AA):
    cs = []
    def __init__(self, cl, i):
        AA.__init__(self, cl, i)
        print("C.__init__", cl, i)
        C.cs.append(self)


print(A('b',0))
print()
print(A('b',1))
print()
print(A('b',0))
print()
print(A('c',0))
print()
print(A('z',0))
