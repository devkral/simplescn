#! /usr/bin/env python3

"""
load parameters, stuff
license: MIT, see LICENSE.txt
"""

import os
import sys
import logging
from getpass import getpass
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


sharedir = os.path.dirname(os.path.realpath(__file__))
# append to pathes
if sharedir not in sys.path:
    sys.path.append(sharedir)

from simplescn import config
from simplescn.config import isself
from simplescn.scnrequest import SCNConnection

# define file_family
if hasattr(socket, "AF_UNIX"):
    file_family = socket.AF_UNIX
else:
    file_family = None

###### signaling ######

class AuthNeeded(Exception):
    reqob = None
    con = None
    def __init__(self, con, reqob):
        self.reqob = reqob
        self.con = con

class AddressFail(Exception):
    msg = ''
    basemsg = '<address>[-<port>]:\n'
    def __str__(self):
        return self.basemsg + self.msg

class EnforcedPortFail(AddressFail):
    msg = 'address is lacking -<port>'
class AddressEmptyFail(AddressFail):
    msg = 'address is empty'
class AddressInvalidFail(AddressFail):
    msg = 'address is invalid'

class InvalidLoadError(Exception):
    msg = ''
    def __str__(self):
        return self.msg
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load is invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
class InvalidLoadLevelError(InvalidLoadError):
    msg = 'Load levels invalid (not high_load>medium_load>low_load)'

class VALError(Exception):
    msg = ''
    basemsg = 'validation failed:\n'
    def __str__(self):
        return self.basemsg + self.msg
class VALNameError(VALError):
    msg = 'Name spoofed/does not match'
class VALHashError(VALError):
    msg = 'Hash does not match'
class VALMITMError(VALError):
    msg = 'MITM-attack suspected: nonce missing or check failed'

resp_st = \
{
    "status":"", # ok/error
    "result": None,
    "error": None
}


### logging ###

def logcheck(ret, level=logging.DEBUG):
    if ret[0]:
        return True
    else:
        if level != 0: # = logging.DEBUG
            try:
                fn, lno, func, sinfo = logging.root.findCaller(False)
            except ValueError: # fails on some interpreters
                fn, lno, func, sinfo = "(unknown file)", 0, "(unknown function)", None
            sinfo = ret[1].get("stacktrace", None)
            message = ret[1].get("msg", "")
            if message == "":
                message = "{levelname}:{line}:{funcname}: crashed".format(levelname=logging.getLevelName(level), line=lno, funcname=func)
            record = logging.root.makeRecord(logging.root.name, level, fn, lno, message, [], None, func, None, sinfo)
            logging.root.handle(record)
        return False

def inp_passw_cmd(msg):
    return getpass(msg+":\n")
pwcallmethodinst = inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)

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

def check_certs(path):
    privpath = "{}.priv".format(path)
    pubpath = "{}.pub".format(path)
    if not os.path.exists(privpath) or not os.path.exists(pubpath):
        return False
    try:
        _context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        _context.load_cert_chain(pubpath, keyfile=privpath, password=lambda: bytes(pwcallmethod("Enter passphrase for decrypting privatekey:"), "utf-8"))
        return True
    except Exception as exc:
        logging.error(exc)
    return False

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

cert_update_header = \
{
    "User-Agent": "simplescn/1.0 (update-cert)",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive'
}


def check_updated_certs(_address, _port, certhashlist, newhash=None, timeout=config.default_timeout, connect_timeout=config.connect_timeout, traverseaddress=None):
    update_list = []
    if None in [_address, _port]:
        logging.error("address or port empty")
        return None
    cont = default_sslcont()
    con = SCNConnection("{}-{}".format(_address, _port), certcontext=cont, connect_timeout=connect_timeout, timeout=timeout, traverseaddress=traverseaddress)
    con.connect()
    if con.sock is None:
        logging.warning("Connection failed")
        return None
    oldhash = dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip())
    if newhash and newhash != oldhash:
        return None
    oldsslcont = con.sock.context
    for _hash, _security in certhashlist:
        con.request("POST", "/usebroken/{hash}".format(hash=_hash), headers=cert_update_header)
        con.sock = con.sock.unwrap()
        con.sock = cont.wrap_socket(con.sock, server_side=False)
        con.sock.do_handshake()
        brokensslcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
        con.sock = con.sock.unwrap()
        # without next line the connection would be unencrypted now
        con.sock = oldsslcont.wrap_socket(con.sock, server_side=False)
        # con.sock.do_handshake()
        ret = con.getresponse()
        if ret.status != 200:
            logging.info("checking cert failed, code: %s, reason: %s", ret.status, ret.reason)
            continue
        if con.sock and oldhash != dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()):
            logging.error("certificate switch detected, stop checking")
            break
        if dhash(brokensslcert) == _hash:
            update_list.append((_hash, _security))
    con.close()
    return update_list


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

def check_classify(func, perm):
    if isinstance(perm, (list, set, tuple)):
        for p in perm:
            if not check_classify(func, p):
                return False
        return True
    if not hasattr(func, "classify"):
        return False
    return perm in func.classify

# signals that method needs admin permission
def classify_admin(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("admin")
    return func
# signals that method only access internal methods and send no requests (e.g. do_request)
def classify_local(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("local")
    return func

# signals that method is experimental
def classify_experimental(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("experimental")
    return func

# signals that method is access method
#access = accessing client/server
def classify_access(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("access")
    return func

def gen_doc_deco(func):
    # skip when no documentation is available
    if func.__doc__ is None:
        return func
    requires = getattr(func, "requires", {})
    optional = getattr(func, "optional", {})
    _docrequires = {}
    _docoptional = {}
    _docfunc, _docreturn = "n.a.", "n.a."
    for line in func.__doc__.split("\n"):
        parsed = line.split(":", 1)
        if len(parsed) != 2:
            continue
        _key = parsed[0].strip().rstrip()
        if _key == "func":
            _docfunc = parsed[1].strip().rstrip()
        if _key == "return":
            _docreturn = parsed[1].strip().rstrip()
        if _key in requires:
            _docrequires[_key] = parsed[1].strip().rstrip()
        if _key in optional:
            _docoptional[_key] = parsed[1].strip().rstrip()
    spacing = " "
    sep = "\n        * "
    if len(getattr(func, "classify", set())) > 0:
        classify = " ({})".format(", ".join(sorted(func.classify)))
    else:
        classify = ""
    # double space == first layer
    newdoc = "  * {}{classify}: {}\n    *{spaces}return: {}\n".format(func.__name__, _docfunc, _docreturn, spaces=spacing, classify=classify)
    if len(requires) == 0:
        newdoc = "{}    *{spaces}requires: n.a.{sep}".format(newdoc, spaces=spacing, sep=sep)
    else:
        newdoc = "{}    *{spaces}requires:\n        *{spaces}".format(newdoc, spaces=spacing)
    for key in requires.keys():
        newdoc = "{}{}({}): {}{sep}".format(newdoc, key, requires[key].__name__, _docrequires.get(key, "n.a."), sep=sep)
    if len(optional) != 0:
        newdoc = "{}\n    *{spaces}optional:\n        *{spaces}".format(newdoc[:-len(sep)], spaces=spacing)
    for key in optional.keys():
        newdoc = "{}{}({}): {}{sep}".format(newdoc, key, optional[key].__name__, _docoptional.get(key, "n.a."), sep=sep)
    func.__origdoc__ = func.__doc__
    func.__doc__ = newdoc[:-len(sep)]
    return func

# args is iterable with (argname, type)
# _moddic is modified
def check_args(_moddict, requires=None, optional=None, error=None):
    if not requires:
        requires = {}
    if not optional:
        optional = {}
    if not error:
        error = []
    search = set()
    if not isinstance(requires, dict):
        raise TypeError("requires wrong type: " + type(requires).__name__)
    if not isinstance(optional, dict):
        raise TypeError("optional wrong type: " + type(optional).__name__)
    search.update(requires.items())
    #_optionallist = [elemoptional[0] for elemoptional in optional]
    search.update(optional.items())
    for argname, value in search:
        _type = value
        if argname not in _moddict:
            if argname in optional:
                continue
            error.append(argname)
            error.append("argname not found")
            return False
        if isinstance(_moddict[argname], _type):
            continue
        if _type is tuple and isinstance(_moddict[argname], list):
            _moddict[argname] = tuple(_moddict[argname])
            continue
        if _type is list and isinstance(_moddict[argname], tuple):
            _moddict[argname] = list(_moddict[argname])
            continue
        # strip array and try again (limitation of www-parser)
        if not _type in (tuple, list) and isinstance(_moddict[argname], (tuple, list)):
            _moddict[argname] = _moddict[argname][0]
        # is a number given as string?
        if _type is int and isinstance(_moddict[argname], str) and _moddict[argname].strip().rstrip().isdecimal():
            _moddict[argname] = int(_moddict[argname])
        # check if everything is right now
        if isinstance(_moddict[argname], _type):
            continue
        error.append(argname)
        error.append("wrong type: {}, {}".format(type(_moddict[argname]).__name__, _moddict[argname]))
        return False
    return True

# args is iterable with (argname, type)
# obdict (=_moddict) is modified
def check_argsdeco(requires=None, optional=None):
    if not requires:
        requires = {}
    if not optional:
        optional = {}
    def func_to_check(func):
        def get_args(self, obdict):
            error = []
            if not check_args(obdict, requires, optional, error=error):
                return False, "check_args failed ({}) arg: {}, reason:{}".format(func.__name__, *error), isself, self.cert_hash
            resp = func(self, obdict)
            if resp is None:
                return False, "bug: no return value in function {}".format(type(func).__name__), isself, self.cert_hash
            if isinstance(resp, bool) or len(resp) == 1:
                if not isinstance(resp, bool):
                    resp = resp[0]
                if resp:
                    return True, "{} finished successfully".format(func.__name__), isself, self.cert_hash
                else:
                    return False, "{} failed".format(func.__name__), isself, self.cert_hash
            elif len(resp) == 2:
                return resp[0], resp[1], isself, self.cert_hash
            else:
                return resp
        get_args.requires = requires
        get_args.optional = optional
        get_args.__doc__ = func.__doc__
        get_args.__name__ = func.__name__
        get_args.classify = getattr(func, "classify", set())
        return gen_doc_deco(get_args)
    return func_to_check

def loglevel_converter(loglevel):
    if isinstance(loglevel, int):
        return loglevel
    elif not loglevel.isdigit():
        if hasattr(logging, loglevel) and isinstance(getattr(logging, loglevel), int):
            return getattr(logging, loglevel)
        raise TypeError("invalid loglevel")
    else:
        return int(loglevel)

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
            string = encode_bo(inp, encoding, charset="utf-8")
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

def check_reference(_reference):
    if _reference is None:
        return False
    if len(_reference) > 100:
        return False
    if not all(c not in "\0'\"\x1A\x7F" for c in _reference):
        return False
    return True

def check_reference_type(_reference_type):
    if _reference_type is None:
        return False
    if len(_reference_type) > config.max_typelength:
        return False
    if not all(c in "0123456789abcdefghijklmnopqrstuvxyz_" for c in _reference_type):
        return False
    return True

def check_security(_security):
    if _security in config.security_states:
        return True
    return False

def check_local(addr):
    if addr in ["127.0.0.1", "::1"]:
        return True
    return False

# DEFAULT_HASHALGORITHM_len for default hash algo
# but None by default for validating hashes of other length
def check_hash(hashstr, length=None):
    if hashstr is None:
        return False
    if length and len(hashstr) != length:
        return False
    # don't allow uppercase as it could confuse clients+servers and lowercase is default
    if not all(c in "0123456789abcdef" for c in hashstr):
        return False
    return True

_badnamechars = " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/"
# no .:- to differ name from ip address
_badnamechars += ".:"

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
        if char in _badnamechars or not char.isprintable():
            pass
        else:
            _name += char
    # name shouldn't be isself as it is used
    if _name == isself:
        _name = "fake_" + isself
    return _name

def check_name(_name, maxlength=config.max_namelength):
    if _name is None:
        return False
    # name shouldn't be too long or 0
    if len(_name) > maxlength or len(_name) == 0:
        return False
    for char in _name:
        # ensure no bad, control characters
        if char in _badnamechars or not char.isprintable():
            return False
    # name shouldn't be isself as it is used
    if _name == isself:
        return False
    return True

def check_typename(_type, maxlength=config.max_typelength):
    if _type is None:
        return False
    # type shouldn't be too long or 0
    if len(_type) > maxlength or len(_type) == 0:
        return False
    # ensure no bad characters
    if not _type.isalpha() or not _type.islower():
        return False
    # type shouldn't be isself as it is used
    if _type == isself:
        return False
    return True

def check_conftype(_value, _converter):
    try:
        if _converter is bool:
            if str(_value) not in ["False", "True"]:
                return False
        else:
            _converter(str(_value))
    except Exception as exc:
        logging.error("invalid value converter: %s value: %s error: %s", _converter, _value, exc)
        return False
    return True

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

