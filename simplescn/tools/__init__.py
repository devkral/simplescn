"""
tools
license: MIT, see LICENSE.txt
"""

import sys
import os
import logging
import datetime
import ssl
import socket
import time
import struct
import traceback
import hashlib
import re
import threading
import json
import selectors
import shutil
import functools

try:
    import cachetools
except ImportError:
    cachetools = None

try:
    import psutil
except ImportError:
    psutil = None

from .. import config
from ..pwrequester import pwcallmethod
from ..config import isself
from ..exceptions import AddressError, AddressEmptyError, AddressLengthError, EnforcedPortError
##### init ######

def generate_certs(_path):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID #,ExtendedKeyUsageOID
    _passphrase = pwcallmethod(config.pwcertgen_prompt)
    assert isinstance(_passphrase, str), "passphrase not str"
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
    os.chmod("{}.priv".format(_path), 0o600)
    with open("{}.pub".format(_path), 'wb') as writeout:
        writeout.write(pubcert)
    os.chmod("{}.pub".format(_path), 0o600)
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
            # warns user every time he launches program
            _name = ""
        with open("{}_name.txt".format(_path), "w") as writeo:
            if prefix == "client":
                writeo.write("{}/{}".format(normalize_name(_name), 0))
            else:
                writeo.write("{}/{}".format(normalize_name(_name), config.server_port))
    if not os.path.exists(_path+"_message.txt"):
        with open("{}_message.txt".format(_path), "w") as writeo:
            writeo.write("<message>")

## pidlock ##
# returns
def get_pidlock(pidpath):
    """ input: path to pidfile
         returns None if found pid == own pid
         returns False if other process has lock
         returns True if pidlock could snatched """
    if not psutil:
        logging.warning("get_pidlock called without psutil")
        return False
    pid = None
    try:
        with open(pidpath, "r") as ro:
            pid = int(ro.read())
    except Exception:
        pid = None
    if pid == os.getpid():
        return None
    if pid and psutil.pid_exists(pid):
        return False
    try:
        if os.path.exists(pidpath):
            os.remove(pidpath)
        fdob = os.open(pidpath, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o444)
        with open(fdob, "w", closefd=True) as wo:
            wo.write(str(os.getpid()))
    except Exception:
        return False
    try:
        with open(pidpath, "r") as ro:
            newpid = int(ro.read())
    except Exception:
        newpid = None
    if os.getpid() == newpid:
        return True
    return False

## file object handler for e.g.representing port ##

def writemsg(path, msg, mode=0o400):
    try:
        fdob = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, mode)
        with open(fdob, "w", closefd=True) as ob:
            ob.write(msg)
    except Exception as exc:
        logging.info(exc)

def cleanup_nlfiles(path):
    for dfile in os.listdir(path):
        if dfile == "lock":
            continue
        os.remove(os.path.join(path, dfile))

class SecdirHandler(object):
    filepath = None
    def __init__(self, path):
        self.filepath = path
    def __del__(self):
        self.cleanup()

    def cleanup(self):
        if self.filepath:
            try:
                shutil.rmtree(self.filepath)
            except Exception as exc:
                if logging:
                    logging.error(exc)
            self.filepath = None

    @classmethod
    def create(cls, path, mode=0o700):
        # check if other instance is running
        if os.path.exists(path):
            # if call doesn't get lock, e.g. other process, no psutil, double calling
            if not get_pidlock(os.path.join(path, "lock")):
                return None
            # can crash if wrong user owns directory
            try:
                os.chmod(path, mode)
                cleanup_nlfiles(path)
            except Exception:
                logging.info("cleanup of existing directory failed, remove and retry")
                shutil.rmtree(path)
                return cls.create(path, mode)
        else:
            os.makedirs(path, mode=mode, exist_ok=False)
            # check if other process has lock, set lock
            if not get_pidlock(os.path.join(path, "lock")):
                return None
        return  cls(path)

##### etc ######

badnamechars = " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/"
# no .:- to differ name from ip address
badnamechars += ".:"
# list seperator (cmd)
badnamechars += ";"

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
    sslcont.options = sslcont.options | ssl.OP_SINGLE_DH_USE \
    | ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
    return sslcont

def gen_sslcont(path):
    sslcont = default_sslcont()
    if os.path.isdir(path):
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(cafile=path)
    return sslcont

_reparseurl = re.compile("(.+)-([0-9]+)$")
@functools.lru_cache(maxsize=config.default_cache_size)
def scnparse_url(url: str, force_port=False):
    if not isinstance(url, str):
        raise AddressError()
    if len(url) == 0:
        raise AddressEmptyError()
    if len(url) > config.max_urllength:
        raise AddressLengthError()
    _urlre = _reparseurl.match(url)
    if _urlre:
        return _urlre.groups()[0], int(_urlre.groups()[1])
    if not force_port:
        return (url, config.server_port)
    else:
        raise EnforcedPortError()

def ttlcaching(ttl):
    def cachew(func):
        if cachetools:
            return cachetools.cached(cache=cachetools.TTLCache(config.default_cache_size, ttl))(func)
        else:
            return func
    return cachew

@ttlcaching(config.urlttl)
def url_to_ipv6(url: str, port: int):
    if url == "":
        return None
    ret = socket.getaddrinfo(url, port, \
    socket.AF_INET6, socket.SOCK_STREAM, flags=socket.AI_V4MAPPED)
    if len(ret) == 0:
        return None
    return (ret[0][4][0], ret[0][4][1])

authrequest_struct = \
{
    "salgo": None,
    "nonce": None,
    "timestamp": None
}

auth_struct = \
{
    "cnonce": None,
    "auth": None,
    "timestamp": None
}

class SCNAuthServer(object):
    request_expire_time = None # in secs
    # auth realms
    nonce = None
    salted_pw = None
    hash_algorithm = None
    serverpubcert_hash = None

    def __init__(self, serverpubcert_hash, hash_algorithm=config.DEFAULT_HASHALGORITHM, \
                 request_expire_time=config.auth_request_expire_time):
        self.hash_algorithm = hash_algorithm
        self.serverpubcert_hash = serverpubcert_hash
        self.request_expire_time = request_expire_time

    def request_auth(self):
        rauth = {}
        rauth["algo"] = self.hash_algorithm
        # send server time, client time should not be used because timeouts are on serverside
        rauth["timestamp"] = int(time.time())
        rauth["snonce"] = self.nonce
        return rauth

    def verify(self, authdict):
        # if not active
        if not self.salted_pw:
            return True
        if not isinstance(authdict, dict):
            logging.warning("authdict is no dict")
            return False
        if len(authdict) == 0:
            return False
        _cnonce = authdict.get("cnonce", None)
        if not isinstance(_cnonce, str):
            logging.warning("no cnonce")
            return False
        _auth = authdict.get("auth", None)
        if not isinstance(_auth, str):
            logging.warning("no auth")
            return False
        _timestamp = authdict.get("timestamp", None)
        if not isinstance(_timestamp, int):
            logging.warning("no timestamp")
            return False
        if _timestamp < int(time.time()) - self.request_expire_time:
            return False
        # don't use bytes() for int; it creates a big array
        if dhash((_cnonce, str(_timestamp)), algo=self.hash_algorithm, prehash=self.salted_pw) == _auth:
            return True
        return False

    def init(self, pwhash):
        # internal salt for memory protection+nonce
        self.nonce = os.urandom(config.salt_size).hex()
        self.salted_pw = dhash((pwhash, self.serverpubcert_hash, self.nonce), algo=self.hash_algorithm)

def scn_hashedpw_auth(hashedpw, authreq_ob, serverhash):
    if hashedpw in ["", None] or not authreq_ob.get("algo", None) or not authreq_ob.get("snonce", None):
        return None
    dauth = auth_struct.copy()
    dauth["timestamp"] = authreq_ob["timestamp"]
    dauth["cnonce"] = os.urandom(config.salt_size).hex()
    # = salted_pw
    dauth["auth"] = dhash((hashedpw, serverhash, authreq_ob["snonce"]), algo=authreq_ob["algo"])
    # = output for verify
    # dont use bytes for int, it creates a giant array
    dauth["auth"] = dhash((dauth["cnonce"], str(dauth["timestamp"])), algo=authreq_ob["algo"], prehash=dauth["auth"])
    return dauth

def extract_senddict(obdict, *args):
    tmp = {}
    for key in args:
        tmp[key] = obdict.get(key, None)
    return tmp

scn_pingstruct = struct.pack(">c511x", b"p")
scn_yesstruct = struct.pack(">c511x", b"y")
scn_nostruct = struct.pack(">c511x", b"y")

#port size, address
addrstrformat = ">HH508s"
def try_traverse(srcaddr, destaddr, connect_timeout=config.connect_timeout, retries=config.traverse_retries):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(srcaddr)
        for count in range(0, retries):
            try:
                sock.connect(destaddr)
                return sock
            except socket.timeout:
                pass
    except Exception as exc:
        logging.info(exc)
    return None

class TraverserDropper(object):
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
        _dstaddr = url_to_ipv6(*_dsttupel)
        if not _dstaddr:
            logging.error("Destination host could not resolved")
            return
        _conaddr = url_to_ipv6(*_contupel)
        if not _conaddr:
            logging.error("Source host could not resolved")
            return
        binaddr = bytes(_conaddr[0], "utf-8")
        construct = struct.pack(addrstrformat, _conaddr[1], len(binaddr), binaddr)
        for elem in range(0, 3):
            self._sock.sendto(construct, _dstaddr)
        if timeout:
            return self.check(timeout)
        else:
            return True

class TraverserHelper(object):
    desttupels = None
    allowed_addresses = None
    active = None
    mutex = None
    def __init__(self, connectsock, srcsock, interval=config.ping_interval):
        self.desttupels = set()
        self.active = True
        self.interval = interval
        self.connectsock = connectsock
        self.srcsock = srcsock
        self.mutex = threading.Lock()
        threading.Thread(target=self._connecter, daemon=True).start()

    def add_desttupel(self, destaddr):
        destaddrtupel = url_to_ipv6(*destaddr)
        if not destaddrtupel:
            logging.error("Destination host could not resolved")
            return False
        with self.mutex:
            if destaddrtupel in self.desttupels:
                # was not added by caller so return False
                return False
            self.desttupels.add(destaddrtupel)
        threading.Thread(target=self._pinger, args=(destaddrtupel,), daemon=True).start()
        return True

    def del_desttupel(self, destaddr):
        destaddrtupel = url_to_ipv6(*destaddr)
        if not destaddrtupel:
            logging.error("Destination host could not resolved")
            return False
        with self.mutex:
            try:
                self.desttupels.remove(destaddrtupel)
            except Exception:
                pass
        return True

    # makes client reachable by server by (just by udp?)
    def _pinger(self, destaddrtupel):
        try:
            while self.active:
                with self.mutex:
                    if destaddrtupel not in self.desttupels:
                        break
                self.srcsock.sendto(scn_pingstruct, destaddrtupel)
                time.sleep(self.interval)
        except Exception as exc:
            logging.info(exc)
            # error: cleanup
            with self.mutex:
                try:
                    self.desttupels.remove(destaddrtupel)
                except Exception:
                    pass
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
                    addrn = url_to_ipv6(addr, port)
                    # prevent ddos
                    if addrn not in self.desttuppels:
                        logging.info("%s not in desttupels", addrn)
                        continue
                    self.connectsock.connect(addrn)
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
    # cannot import from checks (circular dependency)
    if oblist.__class__ is list or oblist.__class__ is tuple:
        oblist2 = oblist
    else:
        oblist2 = [oblist]
    hasher = hashlib.new(algo)
    ret = prehash
    for ob in oblist2:
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

@functools.lru_cache(maxsize=config.default_cache_size)
def encode_bo(inp: bytes, encoding: str, charset="utf-8"):
    splitted = encoding.split(";", 1)
    if len(splitted) == 2:
        #splitted in format charset=utf-8
        split2 = splitted[1].split("=", 1)
        charset = split2[1].strip().rstrip()
    return str(inp, charset, errors="ignore")

# don't cache, elsewise could errors happen because returned dict is changed (mutable return)
def safe_mdecode(inp, encoding: str, charset="utf-8"):
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
            return gen_result(json.loads(string))
        else:
            logging.error("invalid parsing type: %s", enctype)
            return None
    except LookupError:
        logging.error("charset not available")
        return None
    except Exception as exc:
        logging.error(exc)
        return None

def quick_error(err: str):
    """ Quick error """
    #assert isinstance(err, str), "quick_error only accepts str"
    return {"msg": err, "type": ""}

def generate_error(err, withstack=True):
    """ generate error from string/exception/... """
    error = {"msg": "unknown", "type": "unknown"}
    if err is None:
        return error
    error["msg"] = str(err)
    if isinstance(err, str):
        error["type"] = ""
    else:
        error["type"] = type(err).__name__
        if withstack:
            if hasattr(err, "__traceback__"):
                error["stacktrace"] = "".join(traceback.format_tb(err.__traceback__)).replace("\\n", "")
            elif sys.exc_info()[2] is not None:
                error["stacktrace"] = "".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", "")
    return error

def gen_result(res):
    """ generate result """
    if isinstance(res, dict):
        return res
    #elif isinstance(res, bytes):
    #    return {"text": str(res, "ascii", errors="ignore")}
    else:
        return {"text": str(res)}

### logging ###

def logcheck(ret, level=logging.DEBUG):
    """ check if request was successful + log """
    # don't share code because findCaller can only find the last calling function
    # check if return has connection stripped (e.g. access_dict)
    if isinstance(ret[0], bool):
        offset = 0
    else:
        offset = 1
    if ret[offset]:
        return True
    else:
        try:
            fn, lno, func, sinfo = logging.root.findCaller(False)
        except ValueError: # fails on some interpreters
            fn, lno, func, sinfo = "(unknown file)", 0, "(unknown function)", None
        sinfo = ret[1+offset].get("stacktrace", None)
        message = ret[1+offset].get("msg", "")
        if message == "":
            message = "{levelname}:{line}:{funcname}: crashed".format(levelname=logging.getLevelName(level), line=lno, funcname=func)
        record = logging.root.makeRecord(logging.root.name, level, fn, lno, message, [], None, func, None, sinfo)
        logging.root.handle(record)
        return False

def logcheck_con(ret, level=logging.ERROR):
    """ check also if [0] is not None """
    # don't share code because findCaller can only find the last calling function
    if ret[0] and ret[1]:
        return True
    else:
        try:
            fn, lno, func, sinfo = logging.root.findCaller(False)
        except ValueError: # fails on some interpreters
            fn, lno, func, sinfo = "(unknown file)", 0, "(unknown function)", None
        # connection is missing but True
        if not ret[0] and ret[1]:
            message = "{levelname}:{line}:{funcname}: missing connection".format(levelname=logging.getLevelName(level), line=lno, funcname=func)
        else:
            sinfo = ret[2].get("stacktrace", None)
            message = ret[2].get("msg", "")
            if message == "":
                message = "{levelname}:{line}:{funcname}: crashed".format(levelname=logging.getLevelName(level), line=lno, funcname=func)
        record = logging.root.makeRecord(logging.root.name, level, fn, lno, message, [], None, func, None, sinfo)
        logging.root.handle(record)
        return False

def loglevel_converter(loglevel):
    if isinstance(loglevel, int):
        return loglevel
    elif not loglevel.isdigit():
        if hasattr(logging, loglevel) and isinstance(getattr(logging, loglevel), int):
            return getattr(logging, loglevel)
        raise TypeError("invalid loglevel")
    else:
        return int(loglevel)

def rw_socket(sockrw1, sockrw2, timeout=None):
    sfsel = selectors.DefaultSelector()
    sockets = {sockrw1.fileno(): sockrw2, sockrw2.fileno(): sockrw1}
    active = True
    sockrw1.setblocking(False)
    sfsel.register(sockrw1, selectors.EVENT_READ)
    sockrw2.setblocking(False)
    sfsel.register(sockrw2, selectors.EVENT_READ)
    def close():
        sfsel.close()
        sockrw2.close()
        sockrw1.close()
    while active:
        try:
            inpl = sfsel.select(timeout)
            for soc, evnt in inpl:
                ret = soc.fileobj.recv(config.default_buffer_size)
                if ret == b"":
                    active = False
                    close()
                    break
                else:
                    sockets[soc.fd].sendall(ret)
        except (socket.timeout, BrokenPipeError, TimeoutError):
            active = False
            close()
            break
        except Exception as exc:
            active = False
            sfsel.close()
            logging.error(exc)
            break

## for finding local simplescn client ##
def parselocalclient(path, extractipv6=True):
    """ parse simplescn info file; used by getlocalclient()
        extractipv6: extract ipv6 address
        returns: address, use_unix, cert_hash or None """
    try:
        with open(path, "r") as rob:
            pjson = json.load(rob)
        ppath = pjson.get("cserver_unix", None)
        if ppath and os.path.exists(ppath):
            return pjson.get("cserver_unix"), True
        if extractipv6 and "cserver_ip" in pjson:
            soc = socket.create_connection(pjson.get("cserver_ip"), 3)
            if not soc:
                return None
            soc.close()
            return "{}-{}".format(*pjson.get("cserver_ip")), False
        elif "cserver_ip4" in pjson:
            soc = socket.create_connection(pjson.get("cserver_ip4"), 3)
            if not soc:
                return None
            soc.close()
            return "{}-{}".format(*pjson.get("cserver_ip4")), False
        logging.info("Info file exist but no connection found")
    except Exception as exc:
        logging.warning(exc)
    return None

def getlocalclient(extractipv6=True, rundir=config.default_runpath):
    """ parse simplescn info file at default position; use parselocalclient()
        extractipv6: extract ipv6 address
        returns: address, use_unix, cert_hash or None """
    p1 = os.path.join(rundir, "{}-simplescn-client".format(os.getuid()))
    p2 = os.path.join(p1, "info")
    if os.path.exists(p2):
        pidl = get_pidlock(os.path.join(p1, "lock"))
        if not pidl:
            return parselocalclient(p2, extractipv6)
        else:
            # cleanup own and old information
            shutil.rmtree(p1)
    return None
