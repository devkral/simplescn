"""
tools
license: MIT, see LICENSE.txt
"""


import os
import logging
import datetime
import ssl
import socket
import time
import struct

import hashlib
import re
import threading
import json

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID #,ExtendedKeyUsageOID


from simplescn import config
from simplescn.config import isself
from simplescn import pwcallmethod, AddressFail, AddressEmptyFail, EnforcedPortFail





##### init ######

def generate_certs(_path):
    _passphrase = pwcallmethod("(optional) Enter passphrase for encrypting key")
    if _passphrase is not None and not isinstance(_passphrase, str):
        logging.error("passphrase not str, None")
        return False
    if _passphrase != "":
        _passphrase2 = pwcallmethod("Retype:\n")
        if _passphrase != _passphrase2:
            return False
    _key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.key_size,
        backend=default_backend())
    _pub_key = _key.public_key()
    _tname = [x509.NameAttribute(NameOID.COMMON_NAME, 'secure communication nodes'), ]
    _tname.append(x509.NameAttribute(NameOID.COUNTRY_NAME, 'IA'))
    _tname.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'simple-scn'))
    _tname.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'secure communication nodes'))
    #_tname.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "simple.scn"))
    _tname = x509.Name(_tname)
    extensions = []
    builder = x509.CertificateBuilder(issuer_name=_tname,
                                      subject_name=_tname,
                                      public_key=_pub_key,
                                      serial_number=0,
                                      not_valid_before=datetime.date(1970, 1, 1),
                                      not_valid_after=datetime.date(1970, 1, 1),
                                      extensions=extensions)
    cert = builder.sign(_key, config.cert_sign_hash, default_backend())
    if _passphrase == "":
        encryption_algorithm = serialization.NoEncryption()
    else:
        encryption_algorithm = serialization.BestAvailableEncryption(bytes(_passphrase, "utf-8"))
    privkey = _key.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=encryption_algorithm)
    pubcert = cert.public_bytes(serialization.Encoding.PEM)
    with open("{}.priv".format(_path), 'wb') as writeout:
        writeout.write(privkey)
    with open("{}.pub".format(_path), 'wb') as writeout:
        writeout.write(pubcert)
    return True

def init_config_folder(_dir, prefix):
    if not os.path.exists(_dir):
        os.makedirs(_dir, 0o700)
    else:
        os.chmod(_dir, 0o700)
    if not os.path.exists(os.path.join(_dir, "broken")):
        os.makedirs(os.path.join(_dir, "broken"), 0o700)
    else:
        os.chmod(os.path.join(_dir, "broken"), 0o700)
    _path = os.path.join(_dir, prefix)
    if not os.path.exists("{}_name.txt".format(_path)):
        _name = os.getenv("USERNAME")
        if _name in [None, ""]:
            _name = os.getenv("USER")
        if _name in [None, ""]:
            _name = os.getenv("HOME")
            if _name:
                _name = os.path.basename(_name)
        if _name in [None, ""]:
            try:
                _name = socket.gethostname()
            except Exception:
                pass
        if _name in [None, ""]:
            logging.warning("No user name could be detected, init with empty")
            _name = ""
        with open("{}_name.txt".format(_path), "w") as writeo:
            if prefix == "client":
                writeo.write("{}/{}".format(normalize_name(_name), 0))
            else:
                writeo.write("{}/{}".format(normalize_name(_name), config.server_port))
    if not os.path.exists(_path+"_message.txt"):
        with open("{}_message.txt".format(_path), "w") as writeo:
            writeo.write("<message>")

##### etc ######

badnamechars = " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/"
# no .:- to differ name from ip address
badnamechars += ".:"

def normalize_name(_name, maxlength=config.max_namelength):
    if _name is None:
        return None
    # name shouldn't be too long or "", strip also bad chars before length calc
    _name = _name.strip().rstrip()[:maxlength]
    if len(_name) == 0:
        _name = "empty"
        return _name
    _oldname = _name
    _name = ""
    for char in _oldname:
        # ensure no bad, control characters
        if char in badnamechars or not char.isprintable():
            pass
        else:
            _name += char
    # name shouldn't be isself as it is used
    if _name == isself:
        _name = "fake_" + isself
    return _name


def default_sslcont():
    sslcont = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslcont.set_ciphers("HIGH")
    sslcont.options = sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
    return sslcont

def gen_sslcont(path):
    sslcont = default_sslcont()
    if os.path.isdir(path):
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(cafile=path)
    return sslcont


# returns url or ipv6 address unchanged, return converted ipv4 address
# only address, without port
#re_check_ip6 = re.compile("[0-9:]+")
_recheckip4 = re.compile("[0-9.]+")
def convert_ip4_to_6(address):
    if _recheckip4.match(address):
        return "::ffff:{}".format(address)
    else:
        return address

_reparseurl = re.compile("(.*)-([0-9]+)$")
def scnparse_url(url, force_port=False):
    # if isinstance(url, (tuple, list)) == True:
    #     return url
    if not isinstance(url, str):
        raise AddressFail
    if url == "":
        raise AddressEmptyFail
    _urlre = _reparseurl.match(url)
    if _urlre is not None:
        return _urlre.groups()[0], int(_urlre.groups()[1])
    if not force_port:
        return (url, config.server_port)
    raise EnforcedPortFail


authrequest_struct = \
{
    "algo": None,
    "nonce": None,
    "timestamp": None,
    "realm": None
}

auth_struct = \
{
    "auth": None,
    "timestamp": None
}

class scnauth_server(object):
    request_expire_time = None # in secs
    # auth realms
    realms = None
    hash_algorithm = None
    serverpubcert_hash = None

    def __init__(self, serverpubcert_hash, hash_algorithm=config.DEFAULT_HASHALGORITHM, request_expire_time=config.auth_request_expire_time):
        self.realms = {}
        self.hash_algorithm = hash_algorithm
        self.serverpubcert_hash = serverpubcert_hash
        self.request_expire_time = request_expire_time

    def request_auth(self, realm):
        if realm not in self.realms:
            logging.error("Not a valid realm: %s", realm)
        rauth = {}
        rauth["algo"] = self.hash_algorithm
        # send server time, client time should not be used because timeouts are on serverside
        rauth["timestamp"] = str(int(time.time()))
        rauth["realm"] = realm
        rauth["nonce"] = self.realms[realm][1]
        return rauth

    def verify(self, realm, authdict):
        if realm not in self.realms or self.realms[realm] is None:
            return True
        if not isinstance(authdict, dict):
            logging.warning("authdict is no dict")
            return False
        if realm not in authdict:
            #always the case if getting pwrequest
            if len(authdict) > 0:
                logging.debug("realm not in transmitted authdict")
            return False
        if not isinstance(authdict[realm], dict):
            logging.warning("authdicts realm is no dict")
            return False
        if not isinstance(authdict[realm].get("timestamp", None), str):
            logging.warning("no timestamp")
            return False
        if not authdict[realm].get("timestamp", "").isdecimal():
            logging.warning("Timestamp not a number")
            return False
        timestamp = int(authdict[realm].get("timestamp"))
        if timestamp < int(time.time()) - self.request_expire_time:
            return False
        if dhash(authdict[realm].get("timestamp"), self.hash_algorithm, prehash=self.realms[realm][0]) == authdict[realm]["auth"]:
            return True
        return False

    def init_realm(self, realm, pwhash):
        # internal salt for memory protection+nonce
        nonce = os.urandom(config.salt_size).hex()
        self.realms[realm] = (dhash((pwhash, realm, nonce, self.serverpubcert_hash), self.hash_algorithm), nonce)

class scnauth_client(object):
    # save credentials
    save_auth = None
    def __init__(self):
        self.save_auth = {}

    # wrap in dictionary with {realm: return value}
    def auth(self, pw, authreq_ob, serverpubcert_hash, saveid=None):
        realm = authreq_ob.get("realm")
        algo = authreq_ob.get("algo")
        if None in [realm, algo, pw] or pw == "":
            return None
        pre = dhash((dhash(pw, algo), realm), algo)
        if saveid is not None:
            if saveid not in self.save_auth:
                self.save_auth[saveid] = {}
            self.save_auth[saveid][realm] = (pre, algo)
        return self.asauth(pre, authreq_ob, serverpubcert_hash)

    # wrap in dictionary with {realm: return value}
    def asauth(self, pre, authreq_ob, pubcert_hash):
        if pre is None:
            return None
        dauth = auth_struct.copy()
        dauth["timestamp"] = authreq_ob["timestamp"]
        dauth["auth"] = dhash((authreq_ob["nonce"], pubcert_hash, authreq_ob["timestamp"]), authreq_ob["algo"], prehash=pre)
        return dauth

    def saveauth(self, pw, saveid, realm, algo=config.DEFAULT_HASHALGORITHM):
        pre = dhash((dhash(pw, algo), realm), algo)
        if saveid not in self.save_auth:
            self.save_auth[saveid] = {}
        self.save_auth[saveid][realm] = (pre, algo)

    def delauth(self, saveid, realm=None):
        if saveid not in self.save_auth:
            return
        if realm is None:
            del self.save_auth[saveid]
            return
        if realm not in self.save_auth[saveid]:
            return
        del self.save_auth[saveid][realm]

    def reauth(self, saveid, authreq_ob, pubcert_hash):
        if saveid not in self.save_auth:
            return None
        if authreq_ob.get("realm") not in self.save_auth[saveid]:
            return None
        pre, _hashalgo = self.save_auth[saveid][authreq_ob["realm"]]
        if "algo" not in authreq_ob:
            authreq_ob["algo"] = _hashalgo
        return self.asauth(pre, authreq_ob, pubcert_hash)


scn_pingstruct = struct.pack(">c511x", b"p")
scn_yesstruct = struct.pack(">c511x", b"y")
scn_nostruct = struct.pack(">c511x", b"y")

#port size, address
addrstrformat = ">HH508s"
# not needed as far but keep it for future
def traverser_request(_srcaddrtupel, _dstaddrtupel, _contupel):
    if ":" in _dstaddrtupel[0]:
        _socktype = socket.AF_INET6
    else:
        _socktype = socket.AF_INET
    _udpsock = socket.socket(_socktype, socket.SOCK_DGRAM)
    _udpsock.bind(_srcaddrtupel)
    binaddr = bytes(_contupel[0], "utf-8")
    construct = struct.pack(addrstrformat, _contupel[1], len(binaddr), binaddr)
    for elem in range(0, 3):
        _udpsock.sendto(construct, _dstaddrtupel)

class traverser_dropper(object):
    _srcaddrtupel = None
    _sock = None
    active = None
    _checker = None
    def __init__(self, _srcaddrtupel):
        self.active = True
        self._checker = threading.Condition()
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._sock.bind(_srcaddrtupel)
        self._sock.settimeout(None)
        t = threading.Thread(target=self._dropper, daemon=True)
        t.start()

    def _dropper(self):
        while self.active:
            recv = self._sock.recv(512)
            if recv == scn_yesstruct:
                self._checker.notify_all()

    # unaccounted for case multiple clients, but fast
    def check(self, timeout=20):
        try:
            self._checker.wait(timeout)
            return True
        except TimeoutError:
            return False

    def send(self, _dsttupel, _contupel, timeout=None):
        binaddr = bytes(_contupel[0], "utf-8")
        construct = struct.pack(addrstrformat, _contupel[1], len(binaddr), binaddr)
        for elem in range(0, 3):
            self._sock.sendto(construct, _dsttupel)
        if timeout:
            return self.check(timeout)
        else:
            return True

    def send_thread(self, _dsttupel, _contupel):
        self.send(_dsttupel, _contupel, None)



class traverser_helper(object):
    desttupels = None
    active = None
    mutex = None
    def __init__(self, connectsock, srcsock, interval=config.ping_interval):
        self.desttupels = []
        self.active = True
        self.interval = interval
        self.connectsock = connectsock
        self.srcsock = srcsock
        self.mutex = threading.Lock()
        threading.Thread(target=self._connecter, daemon=True).start()

    def add_desttupel(self, destaddrtupel):
        if self.connectsock.family == socket.AF_INET6:
            destaddrtupel = (convert_ip4_to_6(destaddrtupel[0]), destaddrtupel[1])
        self.mutex.acquire()
        if destaddrtupel in self.desttupels:
            return True
        self.desttupels.append(destaddrtupel)
        self.mutex.release()
        threading.Thread(target=self._pinger, args=(destaddrtupel,), daemon=True).start()
        return True

    def del_desttupel(self, destaddrtupel):
        if self.connectsock.family == socket.AF_INET6:
            destaddrtupel = (convert_ip4_to_6(destaddrtupel[0]), destaddrtupel[1])
        self.mutex.acquire()
        try:
            self.desttupels.remove(destaddrtupel)
        except Exception:
            pass
        self.mutex.release()
        return True

    # makes client reachable by server by (just by udp?)
    def _pinger(self, destaddrtupel):
        try:
            while self.active:
                self.mutex.acquire()
                if destaddrtupel not in self.desttupels:
                    self.mutex.release()
                    break
                self.mutex.release()
                self.srcsock.sendto(scn_pingstruct, destaddrtupel)
                time.sleep(self.interval)
        except Exception as exc:
            logging.info(exc)
            # error: cleanup
            self.mutex.acquire()
            try:
                self.desttupels.remove(destaddrtupel)
            except Exception:
                pass
            self.mutex.release()
        # no cleanup needed (if no exception) because a) closed or b) already removed

    # sub __init__ thread
    def _connecter(self):
        while self.active:
            try:
                recv, requesteraddress = self.srcsock.recvfrom(512)
                if len(recv) != 512:
                    # drop invalid packages
                    continue
                unpstru = struct.unpack(addrstrformat, recv)
                port = unpstru[0]
                addr = unpstru[2][:unpstru[1]]
                try:
                    if self.connectsock.family == socket.AF_INET6:
                        addr = convert_ip4_to_6(addr)
                    self.connectsock.connect((addr, port))
                    self.srcsock.sendto(scn_yesstruct, requesteraddress)
                except Exception as exc:
                    self.srcsock.sendto(scn_nostruct, requesteraddress)
                    logging.info(exc)
            except Exception as exc:
                logging.info(exc)


def create_certhashheader(certhash):
    _random = os.urandom(config.token_size).hex()
    return "{};{}".format(certhash, _random), _random

def dhash(oblist, algo=config.DEFAULT_HASHALGORITHM, prehash=""):
    if algo not in config.algorithms_strong:
        logging.error("Hashalgorithm not available: %s", algo)
        return None
    if not isinstance(oblist, (list, tuple)):
        oblist = [oblist,]
    hasher = hashlib.new(algo)
    ret = prehash
    for ob in oblist:
        tmp = hasher.copy()
        tmp.update(bytes(ret, "utf-8"))
        if isinstance(ob, bytes):
            tmp.update(ob)
        elif isinstance(ob, str):
            tmp.update(bytes(ob, "utf-8"))
        else:
            logging.error("Object not hash compatible: %s", ob)
            continue
        ret = tmp.hexdigest()
    return ret


def encode_bo(inp, encoding, charset="utf-8"):
    splitted = encoding.split(";", 1)
    if len(splitted) == 2:
        #splitted in format charset=utf-8
        split2 = splitted[1].split("=", 1)
        charset = split2[1].strip().rstrip()
    return str(inp, charset, errors="ignore")

def safe_mdecode(inp, encoding, charset="utf-8"):
    try:
        # extract e.g. application/json
        enctype = encoding.split(";", 1)[0].strip().rstrip()
        if isinstance(inp, str):
            string = inp
        elif isinstance(inp, bytes):
            string = encode_bo(inp, encoding, charset=charset)
        else:
            logging.error("Invalid type: %s", type(inp))
            return
        if string == "":
            logging.info("Input empty")
            return None
        if enctype == "application/json":
            return json.loads(string)
        else:
            logging.error("invalid parsing type: %s", enctype)
            return None
    except LookupError:
        logging.error("charset not available")
        return None
    except Exception as exc:
        logging.error(exc)
        return None


def rw_socket(sockr, sockw):
    while True:
        try:
            ret = sockr.recv(config.default_buffer_size)
            if ret == b'':
                sockw.close()
                break
            else:
                sockw.sendall(ret)
        except (socket.timeout, BrokenPipeError):
            sockw.close()
            sockr.close()
            break
        except Exception as exc:
            logging.error(exc)
            break

