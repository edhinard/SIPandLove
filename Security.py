#! /usr/bin/python3
# coding: utf-8

import socket
import logging
import weakref
import subprocess
import hashlib
import base64
import binascii
import operator
import random
import re
log = logging.getLogger('Security')

try:
    from . import Milenage
except Exception as e:
    log.warning("cannot import Milenage (%s). AKA authentication is not possible", e)
    Milenage = False

p = subprocess.Popen(['ip', 'xfrm', 'state'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out,err = p.communicate()
if p.returncode != 0:
    log.warning("Cannot run ip xfrm command (%s)", err.decode('utf-8').replace('\n', ' '))
    SEC_AGREE = False
else:
    SEC_AGREE = True


def digest(*, request, realm, nonce, algorithm, cnonce, qop, nc, username, password):
    log.info("--DIGEST --")
    uri = str(request.uri)
    if qop:
        qop = qop.lower()
        for q in qop.split(','):
            if q == 'auth':
                qop = 'auth'
                break
            if q == 'auth-int':
                qop = 'auth_int'
                break
        else:
            log.warning("ignoring unknown qop %s. auth or auth-int was expected", qop)
            qop = None
    log.info("realm     = %r", realm)
    log.info("uri       = %r", uri)
    log.info("username  = %r", username)
    log.info("nonce     = %r", nonce)
    log.info("algorithm = %r", algorithm)
    log.info("qop       = %r", qop)
    params = dict(realm = realm,
                  uri = uri,
                  username = username,
                  nonce = nonce,
                  algorithm = algorithm,
                  qop=qop,
    )

    log.info("password  = %r", password)
    ha1 = md5hash(username, realm, password)
    log.info("ha1       = %r", ha1)
    if algorithm and algorithm.lower() == 'md5-sess':
        ha1 = md5hash(ha1, nonce, cnonce)
        params.update(cnonce=cnonce)
        log.info("ha1       = %r", ha1)

    if not qop or qop == 'auth':
        ha2 = md5hash(request.method, uri)
    else:
        ha2 = md5hash(request.method, uri, md5hash(request.body))
    log.info("ha2       = %r", ha2)

    if not qop:
        response = md5hash(ha1, nonce, ha2)
    else:
        response = md5hash(ha1, nonce, "{:08x}".format(nc), cnonce, qop, ha2)
        params.update(cnonce=cnonce, nc=nc)
        log.info("cnonce    = %r", cnonce)
        log.info("nc        = %r", nc)
    params.update(response=response)
    log.info("-----------")
    log.info("response  = %r", response)
    log.info("")

    return params

def md5hash(*params):
    s = b':'.join((param.encode('utf-8') if isinstance(param, str) else param for param in params))
    return hashlib.md5(s).hexdigest()

def AKA(nonce, K, OP):
    log.info("--- AKA ---")
    if not Milenage:
        raise Exception("Milenage not present")
    log.info("OP   = %s", OP.hex())
    log.info("K    = %s", K.hex())
    log.info("nonce= %r", nonce)
    try:
        nonce = base64.b64decode(nonce, validate=True)
    except binascii.Error:
        raise Exception("nonce value is not base64 encoded")
    log.info("nonce= %s", nonce.hex())
    if len(nonce) < 32:
        raise Exception("nonce is {} bytes long (at least 32 expected)".format(len(nonce)))
    RAND = nonce[:16]
    SQNxorAK = nonce[16:22]
    AMF = nonce[22:24]
    MAC = nonce[24:32]
    log.info("RAND = %s", RAND.hex())
    log.info("SQNAK= %s", SQNxorAK.hex())
    log.info("AMF  = %s", AMF.hex())
    log.info("MAC  = %s", MAC.hex())

    log.info("-----------")
    milenage = Milenage.Milenage(OP=OP)
    RES, CK, IK, AK = milenage.f2345(K, RAND)
    log.info("RES  = %s", RES.hex())
    log.info("IK   = %s", IK.hex())
    log.info("CK   = %s", CK.hex())
    log.info("AK   = %s", AK.hex())
    SQN = bytes(map(operator.__xor__, SQNxorAK, AK)) 
    log.info("SQN  = %s", SQN.hex())
    XMAC = milenage.f1(K, RAND, SQN, AMF)
    log.info("XMAC = %s", XMAC.hex())
    if MAC != XMAC:
        raise Exception("XMAC does not match MAC")
    else:
        log.info("XMAC and MAC match")
    log.info("")

    return RES, IK, CK


AUTH_DICT = {
#    'hmac-md5-96'   : 'md5 0x{}',
    'hmac-sha-1-96' : 'sha1 0x{}'
}
ENC_DICT = {
    'null'          : 'cipher_null ""',
#    'des-ede3-cbc'  : 'des3_ede 0x{}',
#    'aes-cbc'       : 'aes 0x{}'
}
IPSEC_ALGS = tuple(AUTH_DICT.keys())
IPSEC_EALGS = tuple(ENC_DICT.keys())

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
        self.auth = None
        self.enc = None
        self.remote = SA.Struct()
        self.remote.ip = remoteip
        
        self.local = SA.Struct()
        self.local.ip = localip
        self.local.spic = self.allocspi()
        self.local.spis = self.allocspi()
        self.reserveports()

        self.xfrm('''policy add
                         src {local.ip} dst 0.0.0.0/0 sport {local.portc}
                         dir out
                         tmpl src 0.0.0.0 dst 0.0.0.0/0 proto esp mode transport''')
        self.xfrm('''policy add
                         src {local.ip} dst 0.0.0.0/0 sport {local.ports}
                         dir out
                         tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode transport''')
        self.xfrm('''policy add
                         src 0.0.0.0/0 dst {local.ip} dport {local.portc}
                         dir in
                         tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode transport''')
        self.xfrm('''policy add
                         src 0.0.0.0/0 dst {local.ip} dport {local.ports}
                         dir in
                         tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode transport''')
        
        self.state = 'initialized'


    def finalize(self, *, spic, spis, portc, ports, ik, ck, alg, ealg):
        if self.state != 'initialized':
            raise RuntimeError("SA not in initialized state")

        self.remote.spic = spic
        self.remote.spis = spis
        self.remote.portc = portc
        self.remote.ports = ports

        self.auth = AUTH_DICT[alg].format(ik.hex())
        self.enc = ENC_DICT[ealg].format(ck.hex())

        # SA #1 from local portc to remote ports with remote spis
        self.xfrm('''state add
                         src {local.ip} dst {remote.ip}
                         proto esp spi {remote.spis} mode transport
                         replay-window 32
                         auth {auth} enc {enc}
                         sel src {local.ip} dst {remote.ip} sport {local.portc} dport {remote.ports}''')
        
        # SA #2 from remote ports to local portc with local spic
        self.xfrm('''state update
                         src {remote.ip} dst {local.ip}
                         proto esp spi {local.spic} mode transport
                         replay-window 32
                         auth {auth} enc {enc}
                         sel src {remote.ip} dst {local.ip} sport {remote.ports} dport {local.portc}''')
        
        # SA #3 from local ports to remote portc with remote spic
        self.xfrm('''state add
                         src {local.ip} dst {remote.ip}
                         proto esp spi {remote.spic} mode transport
                         replay-window 32
                         auth {auth} enc {enc}
                         sel src {local.ip} dst {remote.ip} sport {local.ports} dport {remote.portc}''')

        # SA #4 from remote portc to local ports with local spis
        self.xfrm('''state update
                         src {remote.ip} dst {local.ip}
                         proto esp spi {local.spis} mode transport
                         replay-window 32
                         auth {auth} enc {enc}
                         sel src {remote.ip} dst {local.ip} sport {remote.portc} dport {local.ports}''')

        self.state = 'created'


    def terminate(self):
        if self.state == 'finished':
            return

        # flush SPDB
        self.xfrm('''policy del src {local.ip} dst 0.0.0.0/0 sport {local.portc} dir out''')
        self.xfrm('''policy del src {local.ip} dst 0.0.0.0/0 sport {local.ports} dir out''')
        self.xfrm('''policy del src 0.0.0.0/0 dst {local.ip} dport {local.portc} dir in''')
        self.xfrm('''policy del src 0.0.0.0/0 dst {local.ip} dport {local.ports} dir in''')

        if self.state == 'initialized':
            # free pre-allocated SPI
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''')

        elif self.state == 'created':
            # flush SADB
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spis}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''')
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spic}''')
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''')

        # close sockets
        self.local.tcpc.close()
        self.local.udpc.close()
        self.local.tcps.close()
        self.local.udps.close()

        self.state = 'finished'


    def xfrm(self, cmd):
        cmd = ['ip', 'xfrm'] + cmd.format(local=self.local, remote=self.remote, auth=self.auth, enc=self.enc).split()
        p = subprocess.Popen([a.strip('"') for a in cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out,err = p.communicate()
        log.info("%s --> %d", ' '.join(cmd), p.returncode)
        if p.returncode != 0:
            raise Exception("ip xfrm --> {}".format(err.decode('utf-8')))
        return out


    SPI_RE = re.compile(br'spi (0x[0-9a-f]+)')
    def allocspi(self):
        resp = self.xfrm('''state allocspi src {remote.ip} dst {local.ip} proto esp''')
        m = SA.SPI_RE.search(resp)
        if m:
            return int(m.group(1), 16)
        else:
            raise Exception("cannot allocate SPI")


    def reserveports(self):
        self.local.portc, self.local.tcpc, self.local.udpc = self.reserveoneport()
        self.local.ports, self.local.tcps, self.local.udps = self.reserveoneport()


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
