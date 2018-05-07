#! /usr/bin/python3
# coding: utf-8

import socket
import logging
import weakref
import subprocess
import base64
import binascii
import operator
import random
import re
log = logging.getLogger('Security')

try:
    from . import Milenage
except Exception as e:
    log.warning("cannot import Milenage (%s). AKAv1 authentication is not possible", e)
    Milenage = False


def AKA(nonce, K, OP):
    if not Milenage:
        raise Exception("Milenage not present")
    try:
        nonce = base64.b64decode(nonce, validate=True)
    except binascii.Error:
        raise Exception("nonce value is not base64 encoded")
    if len(nonce) < 32:
        raise Exception("nonce is {} bytes long (at least 32 expected)".format(len(nonce)))
    RAND = nonce[:16]
    SQNxorAK = nonce[16:22]
    AMF = nonce[22:24]
    MAC = nonce[24:32]

    milenage = Milenage.Milenage(OP=OP)
    RES, CK, IK, AK = milenage.f2345(K, RAND)
    SQN = bytes(map(operator.__xor__, SQNxorAK, AK)) 
    XMAC = milenage.f1(K, RAND, SQN, AMF)
    log.info("OP  =%s", OP.hex())
    log.info("K   =%s", K.hex())
    log.info("RAND=%s", RAND.hex())
    log.info("AK  =%s", AK.hex())
    log.info("SQN =%s", SQN.hex())
    log.info("AMF =%s", AMF.hex())
    log.info("MAC =%s", MAC.hex())
    log.info("XMAC=%s", XMAC.hex())
    log.info("RES =%s", RES.hex())
    log.info("IK  =%s", IK.hex())
    log.info("CK  =%s", CK.hex())
    if MAC != XMAC:
        raise Exception("XMAC does not match MAC")

    return RES, IK, CK


class SA:
#
# local ip         |         remote ip
#                      
#        ---------(1)- spis ->
#  portc                       ports
#        <- spic -(2)---------
#
#
#        ---------(3)- spic ->
#  ports                       portc
#        <- spis -(4)---------
#
    sas = weakref.WeakSet()
    def __new__(cls, *args, **kwargs):
        sa = super().__new__(cls)
        SA.sas.add(sa)
        return sa

    class Struct:
        pass

    def __init__(self, localip, remoteip):
        self.state = 'finished'
        self.remote = SA.Struct()
        self.remote.ip = remoteip
        
        self.local = SA.Struct()
        self.local.ip = localip
        self.local.spic = self.allocspi()
        self.local.spis = self.allocspi()
        
        self.reserveports()
        
        self.state = 'initialized'


    def finalize(self, *, spic, spis, portc, ports, ik, ck, alg, ealg):
        if self.state != 'initialized':
            raise RuntimeError("SA not in initialized state")

        self.remote.spic = spic
        self.remote.spis = spis
        self.remote.portc = portc
        self.remote.ports = ports

        self.local.auths  = self.local.authc  = 'md5 0x{}'.format(ik.hex())
        self.local.encs   = self.local.encc   = 'cipher_null ""'
        self.remote.auths = self.remote.authc = 'md5 0x{}'.format(ik.hex())
        self.remote.encs  = self.remote.encc  = 'cipher_null ""'

        # SA #1 from local:portc to remote:ports with remote spis
        self.remote.reqids = self.newreqid()
        self.xfrm('''state  add
                         src {local.ip} dst {remote.ip} proto esp spi {remote.spis} 
                         mode transport auth {remote.auths} enc {remote.encs}
                         reqid {remote.reqids}
                         replay-window 32''')
        self.xfrm('''policy add
                         src {local.ip} dst {remote.ip} sport {local.portc} dport {remote.ports}
                         dir out
                         tmpl src {local.ip} dst {remote.ip} proto esp mode transport
                         reqid {remote.reqids}''')
        
        # SA #2 from remote:ports to local:portc with local spic
        self.local.reqidc = self.newreqid()
        self.xfrm('''state  update 
                         src {remote.ip} dst {local.ip} proto esp spi {local.spic}
                         mode transport auth {local.authc} enc {local.encc}
                         reqid {local.reqidc}
                         replay-window 32''')
        self.xfrm('''policy add 
                         src {remote.ip} dst {local.ip} sport {remote.ports} dport {local.portc}
                         dir in
                         tmpl src {remote.ip} dst {local.ip} proto esp mode transport
                         reqid {local.reqidc}''')
        
        # SA #3 from local:ports to remote:portc with remote spic
        self.remote.reqidc = self.newreqid()
        self.xfrm('''state  add 
                         src {local.ip} dst {remote.ip} proto esp spi {remote.spic}
                         mode transport auth {remote.authc} enc {remote.encc}
                         reqid {remote.reqidc}
                         replay-window 32''')
        self.xfrm('''policy add
                         src {local.ip} dst {remote.ip} sport {local.ports} dport {remote.portc}
                         dir out
                         tmpl src {local.ip} dst {remote.ip} proto esp mode transport
                         reqid {remote.reqidc}''')

        # SA #4 from remote:ports to local:portc with local spis
        self.local.reqids = self.newreqid()
        self.xfrm('''state  update
                         src {remote.ip} dst {local.ip} proto esp spi {local.spis}
                         mode transport auth {local.auths} enc {local.encs}
                         reqid {local.reqids}
                         replay-window 32''')
        self.xfrm('''policy add
                         src {remote.ip} dst {local.ip} sport {remote.portc} dport {local.ports}
                         dir in
                         tmpl src {remote.ip} dst {local.ip} proto esp mode transport
                         reqid {local.reqids}''')

        self.state = 'created'


    def terminate(self):
        if self.state == 'finished':
            return

        if self.state == 'initialized':
            # free pre-allocated SPI
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''')
            
        elif self.state == 'created':
            # flush SADB and SPDB
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spis}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''')
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spic}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''')
            
            self.xfrm('''policy del src {local.ip} dst {remote.ip} sport {local.portc} dport {remote.ports} dir out''')
            self.xfrm('''policy del src {remote.ip} dst {local.ip} sport {remote.ports} dport {local.portc} dir in''')
            self.xfrm('''policy del src {local.ip} dst {remote.ip} sport {local.ports} dport {remote.portc} dir out''')
            self.xfrm('''policy del src {remote.ip} dst {local.ip} sport {remote.portc} dport {local.ports} dir in''')

        # close sockets
        self.tcpc.close()
        self.udpc.close()
        self.tcps.close()
        self.udps.close()

        self.state = 'finished'


    def xfrm(self, cmd):
        cmd = ['ip', 'xfrm'] + cmd.format(local=self.local, remote=self.remote).split()
        p = subprocess.Popen([a.strip('"') for a in cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out,err = p.communicate()
        log.info("%s --> %d", ' '.join(cmd), p.returncode)
        if p.returncode != 0:
            raise Exception(err.decode('utf-8'))
        return out


    SPI_RE = re.compile(br'spi (0x[0-9a-f]+)')
    def allocspi(self):
        resp = self.xfrm('''state allocspi src {remote.ip} dst {local.ip} proto esp''')
        m = SA.SPI_RE.search(resp)
        if m:
            return int(m.group(1), 16)
        else:
            raise Exception("cannot allocate SPI")


    def newreqid(self):
        while True:
            reqid = random.getrandbits(32)
            resp = self.xfrm('state list reqid {}'.format(reqid))
            if not resp:
                break
        return reqid


    def reserveports(self):
        self.local.portc, self.tcpc, self.udpc = self.reserveoneport()
        self.local.ports, self.tcps, self.udps = self.reserveoneport()


    def reserveoneport(self):
        #  - open a TCP socket
        #  - bind it on local ip (let the system find the port)
        #  - open a UDP socket
        #  - bind it on local ip with the same port number
        # repeat until success (the last action can fail) or raise an error
        tobeclosed = []
        try:
            for _ in range(10):
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.bind((self.local.ip, 0))
                port = tcp.getsockname()[1]
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    udp.bind((self.local.ip, port))
                except:
                    tobeclosed.append(tcp)
                    udp.close()
                else:
                    break
            else:
                raise Exception("unable to find a common port number for TCP and UDP")
        finally:
            for t in tobeclosed:
                t.close()

        return port,tcp,udp
            
if __name__ == '__main__':
    import sys
    log.setLevel('DEBUG')
    log.addHandler(logging.StreamHandler(sys.stdout))
    
    LOCALIP = '172.20.35.253'
    REMOTEIP = '194.2.137.40'
    # check with wireshark that IP packets sent to REMOTEIP have ESP with the right SPI

    sa1 = SA(LOCALIP, REMOTEIP)
    sa1.finalize(portc=111, ports=112, spic=111, spis=112, ik=b'\x01\x01')

    sa2 = SA(LOCALIP, REMOTEIP)
    sa2.finalize(portc=221, ports=222, spic=221, spis=222, ik=b'\x02\x02')

    sa1.udpc.sendto(b'x', (REMOTEIP, 112))
    sa1.tcpc.settimeout(1)
    try:
        sa1.tcpc.connect((REMOTEIP, 112))
    except:
        pass

    sa2.udpc.sendto(b'x', (REMOTEIP, 222))
    sa2.tcpc.settimeout(1)
    try:
        sa2.tcpc.connect((REMOTEIP, 222))
    except:
        pass
