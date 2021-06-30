#! /usr/bin/python3
# coding: utf-8

import sys
import socket
import logging
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

SEC_AGREE = False
for m in sys.modules:
    if m.split('.',1)[0].startswith('scapy'):
        try:
            import scapy.all
            if not scapy.all.HMAC:
                log.warning("Scapy is loaded but no crypto algo available. Try to run > pip3 install cryptography")
                break
            SEC_AGREE = 'scapy'
            break
        except Exception as e:
            log.warning("Scapy seems to be loaded but import scapy.all triggers this: {!r}".format(e))
            break
else:
    log.warning("scapy is not pre-loaded")
if not SEC_AGREE:
    p = subprocess.Popen(['ip', 'xfrm', 'state'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out,err = p.communicate()
    if p.returncode == 0:
        SEC_AGREE = 'xfrm'
    else:
        log.warning("cannot run xfrm command (try as root)")

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

def AKA(nonce, identity):
    try:
        nonce = base64.b64decode(nonce, validate=True)
    except binascii.Error:
        raise Exception("nonce value is not base64 encoded")
    if len(nonce) < 32:
        raise Exception("nonce is {} bytes long (at least 32 expected)".format(len(nonce)))
    usim = identity.get('usim')
    if usim:
        log.info("--- AKA by USIM ---")
        RAND = nonce[:16]
        AUTN = nonce[16:32]
        log.info("RAND = %s", RAND.hex())
        log.info("AUTN = %s", AUTN.hex())

        ret = usim.authenticate(list(RAND), list(AUTN), ctx='3G')
        if len(ret) == 1:
            log.logandraise(Exception('AUTS = %s. need to synchronize USIM', ret[0].hex()))
        res,ck,ik,kc = ret
        assert(len(res) == 8)
        assert(len(ck) == 16)
        assert(len(ik) == 16)
        RES = bytes(res)
        CK = bytes(ck)
        IK = bytes(ik)

        log.info("RES  = %s", RES.hex())
        log.info("IK   = %s", IK.hex())
        log.info("CK   = %s", CK.hex())
        return RES, IK, CK

    log.info("--- AKA ---")
    if not Milenage:
        log.logandraise(Exception("Milenage not present"))
    K = identity.pop('K', None)
    if K is None:
        log.warning("missing K in credentials. Using 0")
        K = 16*b'\x00'
    if len(K) < 16:
        log.warning("K too short. Padding with 0")
        K = K + (16-len(K))*b'\x00'
    if len(K) > 16:
        log.warning("K too long. Keeping MSB")
        K = K[:16]
    OP = identity.pop('OP', None)
    if OP is None:
        log.warning("missing OP in credentials. Using 0")
        OP = 16*b'\x00'
    if len(OP) < 16:
        log.warning("OP too short. Padding with 0")
        OP = OP + (16-len(OP))*b'\x00'
    if len(OP) > 16:
        log.warning("OP too long. Keeping MSB")
        OP = OP[:16]
    log.info("OP   = %s", OP.hex())
    log.info("K    = %s", K.hex())
    log.info("nonce= %s", nonce.hex())
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


# =============================================================================
# Security Association

IPSEC_ALGS = IPSEC_EALGS = ()
SA = None
def initsecagree():
    global IPSEC_ALGS, IPSEC_EALGS
    global SA
    if SA:
        return
    if SEC_AGREE == 'xfrm':
        log.info("will use xfrm for SA")
        SA = SAxfrm
    elif SEC_AGREE == 'scapy':
        log.info("will use scapy for SA")
        SA = SAscapy
    else:
        log.logandraise(Exception('sec-agree is not possible: scapy not preloaded and cannot run xfrm'))
    IPSEC_ALGS = tuple(SA.AUTH_DICT.keys())
    IPSEC_EALGS = tuple(SA.ENC_DICT.keys())

#
# local ip                remote ip
#
#        ---------- spis ->
#  portc                    ports
#        <- spic ----------
#
#
#        ---------- spic ->
#  ports                    portc
#        <- spis ----------
#
class Struct:
    pass
class SAxfrm:
    AUTH_DICT = {
        'hmac-sha-1-96' : 'sha1 0x{}',
        'hmac-md5-96'   : 'md5 0x{}',
#        'unknown-auth'   : 'xxx',
    }
    ENC_DICT = {
        'null'          : 'cipher_null ""',
        #'des-ede3-cbc'  : 'des3_ede 0x{}',
        #'aes-cbc'       : 'aes 0x{}'
    }

    def __init__(self, localip, remoteip):
        self.state = 'finished'
        self.auth = None
        self.enc = None
        self.remote = Struct()
        self.remote.ip = remoteip
        
        self.local = Struct()
        self.local.ip = localip
        self.local.spic = self.allocspi()
        self.local.spis = self.allocspi()
        self.local.portc, self.local.tcpc, self.local.udpc = self.reserveoneport()
        self.local.ports, self.local.tcps, self.local.udps = self.reserveoneport()

        self.xfrm('''policy add
                         src {local.ip} dst 0.0.0.0/0 sport {local.portc}
                         dir out
                         tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode transport''')
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

        self.auth = SAxfrm.AUTH_DICT[alg].format(ik.hex())
        self.enc = SAxfrm.ENC_DICT[ealg].format(ck.hex())

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
        self.xfrm('''policy del src {local.ip} dst 0.0.0.0/0 sport {local.portc} dir out''', False)
        self.xfrm('''policy del src {local.ip} dst 0.0.0.0/0 sport {local.ports} dir out''', False)
        self.xfrm('''policy del src 0.0.0.0/0 dst {local.ip} dport {local.portc} dir in''', False)
        self.xfrm('''policy del src 0.0.0.0/0 dst {local.ip} dport {local.ports} dir in''', False)

        if self.state == 'initialized':
            # free pre-allocated SPI
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''', False)
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''', False)

        elif self.state == 'created':
            # flush SADB
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spis}''', False)
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spic}''', False)
            self.xfrm('''state del src {local.ip} dst {remote.ip} proto esp spi {remote.spic}''', False)
            self.xfrm('''state del src {remote.ip} dst {local.ip} proto esp spi {local.spis}''', False)

        # close sockets
        self.local.tcpc.close()
        self.local.udpc.close()
        self.local.tcps.close()
        self.local.udps.close()

        self.state = 'finished'

    def xfrm(self, cmd, raiseonerror=True):
        cmd = ['ip', 'xfrm'] + cmd.format(local=self.local, remote=self.remote, auth=self.auth, enc=self.enc).split()
        p = subprocess.Popen([a.strip('"') for a in cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out,err = p.communicate()
        log.info("%s --> %d", ' '.join(cmd), p.returncode)
        if p.returncode != 0 and raiseonerror:
            raise Exception("ip xfrm --> {}".format(err.decode('utf-8')))
        return out

    SPI_RE = re.compile(br'spi (0x[0-9a-f]+)')
    def allocspi(self):
        resp = self.xfrm('''state allocspi src {remote.ip} dst {local.ip} proto esp''')
        m = SAxfrm.SPI_RE.search(resp)
        if m:
            return int(m.group(1), 16)
        else:
            raise Exception("cannot allocate SPI")

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

class SASocket(socket.socket):
    def __init__(self, localip, localport, recvspi):
        self.localip = localip
        self.localport = localport
        self.recvspi = recvspi
        self.rxsa = self.txsa = None
        # rx part of the object
        super().__init__(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
        self.bind((self.localip, socket.IPPROTO_ESP))
        # tx part
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    def associate(self, remoteip, remoteport, sendspi, alg, ik, ealg, ck):
        assert((self.rxsa==None) and (self.txsa==None))
        self.remoteip = remoteip
        self.remoteport = remoteport
        if ealg == 'NULL':
            ck = None
        self.rxsa = scapy.all.SecurityAssociation(scapy.all.ESP,
                                                  spi=self.recvspi,
                                                  crypt_algo=ealg,
                                                  crypt_key=ck,
                                                  auth_algo=alg,
                                                  auth_key=ik)
        self.txsa = scapy.all.SecurityAssociation(scapy.all.ESP,
                                                  spi=sendspi,
                                                  crypt_algo=ealg,
                                                  crypt_key=ck,
                                                  auth_algo=alg,
                                                  auth_key=ik)

    def recvfrom(self, bufsize):
        assert((self.rxsa!=None) and (self.txsa!=None))
        buf = b''
        data = super().recv(bufsize)
        esp = scapy.all.IP(data)
        try:
            esp = self.rxsa.decrypt(esp)
            remoteip = esp[scapy.all.IP].src
            remoteport = esp[scapy.all.UDP].sport
            buf = bytes(esp[scapy.all.Raw])
        except Exception as e:
            return b'',(None,0)
        if buf and (remoteip==self.remoteip) and (remoteport==self.remoteport):
            return buf,(remoteip,remoteport)
        else:
            return b'',(None,0)

    def sendto(self, packet, remoteaddr):
        assert((self.rxsa!=None) and (self.txsa!=None))
        remoteip,remoteport = remoteaddr
        assert(remoteip == self.remoteip)
        assert(remoteport == self.remoteport)
        ip = scapy.all.IP(src=self.localip, dst=remoteip)/scapy.all.UDP(sport=self.localport, dport=remoteport)/scapy.all.Raw(packet)
        esp = self.txsa.encrypt(ip)
        for frag in scapy.all.fragment(esp):
            self.tx.sendto(bytes(frag), 0, (remoteip, 0))

class SAscapy:
    AUTH_DICT = {
        'hmac-sha-1-96' : 'HMAC-SHA1-96',
        'hmac-md5-96'   : 'HMAC-MD5-96'
    }
    ENC_DICT = {
        'null'          : 'NULL',
    }

    def __init__(self, localip, remoteip):
        self.state = 'finished'
        self.remote = Struct()
        self.remote.ip = remoteip
        self.local = Struct()
        self.local.ip = localip
        self.local.spic = random.randint(10000, 20000)
        self.local.spis = random.randint(10000, 20000)
        self.local.portc = random.randint(10000, 20000)
        self.local.ports = random.randint(10000, 20000)
        self.local.udpc = SASocket(self.local.ip, self.local.portc, self.local.spic)
        self.local.udps = SASocket(self.local.ip, self.local.ports, self.local.spis)
        self.state = 'initialized'

    def finalize(self, *, spic, spis, portc, ports, ik, ck, alg, ealg):
        if self.state != 'initialized':
            raise RuntimeError("SA not in initialized state")
        self.remote.spic = spic
        self.remote.spis = spis
        self.remote.portc = portc
        self.remote.ports = ports
        self.local.udpc.associate(self.remote.ip, self.remote.ports, self.remote.spis, SAscapy.AUTH_DICT[alg], ik, SAscapy.ENC_DICT[ealg], ck)
        self.local.udps.associate(self.remote.ip, self.remote.portc, self.remote.spic, SAscapy.AUTH_DICT[alg], ik, SAscapy.ENC_DICT[ealg], ck)
        self.state = 'created'

    def terminate(self):
        if self.state == 'finished':
            return
        # close sockets
        self.local.udpc.close()
        self.local.udps.close()
        self.state = 'finished'


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
