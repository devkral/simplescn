#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

import os, sys

sharedir = os.path.dirname(os.path.realpath(__file__))
# append to pathes
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import logging
import ipaddress
from getpass import getpass
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
from urllib import parse
from http.client import HTTPSConnection 
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver


from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID #,ExtendedKeyUsageOID

# load parameters in simplescn namespace
# don't load directly from parameters
# because parameters can be overwritten by parameters_overwrite
try:
    from simplescn.parameters_overwrite import *
except ImportError:
    from simplescn.parameters import *
socket.setdefaulttimeout(default_timeout)


###### signaling ######

class AddressFail(Exception):
    msg = '"<address>[:<port>]": '
class EnforcedPortFail(AddressFail):
    msg = 'address is lacking "-<port>"'
class AddressEmptyFail(AddressFail):
    msg = '{} address is empty'.format(AddressFail.msg)
class AddressInvalidFail(AddressFail):
    msg = '{} address is invalid'.format(AddressFail.msg)

class InvalidLoadError(Exception):
    pass
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load is invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
    args = (msg, )
class InvalidLoadLevelError(InvalidLoadError):
    msg = 'Load levels invalid (not high_load>medium_load>low_load)'
    args = (msg, )

class VALError(Exception):
    msg = 'validation failed'
    args = (msg, )
class VALNameError(VALError):
    msg = 'Name spoofed/does not match'
    args = (msg, )
class VALHashError(VALError):
    msg = 'Hash does not match'
    args = (msg, )
class VALMITMError(VALError):
    msg = 'MITM-attack suspected: nonce missing or check failed'
    args = (msg, )

resp_st={
"status":"", #ok, error
"result": None,
"error": None
}


def generate_error(err):
    error={"msg": "unknown", "type":"unknown"}
    if err is None:
        return error
    if hasattr(err, "msg"):
        error["msg"] = str(err.msg)
    else:
        error["msg"] = str(err)
    if isinstance(err,str) == True:
        error["type"] = ""
    else:
        error["type"] = type(err).__name__
        if hasattr(err,"__traceback__"):
            error["stacktrace"] = "".join(traceback.format_tb(err.__traceback__)).replace("\\n", "") #[3]
        elif sys.exc_info()[2] is not None:
            error["stacktrace"] = "".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", "")
    return error # json.dumps(error)

def generate_error_deco(func):
    def get_args(self,*args, **kwargs):
        resp = func(self, *args,**kwargs)
        if len(resp) == 4:
            _name = resp[2]
            _hash = resp[3]
        else:
            _name = isself
            _hash = self.cert_hash
        if resp[0] == False:
            #ry:
            #    json.loads(resp[1])
            #except ValueError:
            return False, generate_error(resp[1]), _name, _hash
        return resp
    return get_args

def gen_result(res, status):
    """ generate result """
    s = resp_st.copy()
    if status == True:
        s["status"] = "ok"
        s["result"] = res
        del s["error"]
    else:
        s["status"] = "error"
        s["error"] = res
        del s["result"]
    return s

def check_result(obdict, status):
    """ is result valid """
    if obdict is None:
        return False
    if "status" not in obdict:
        return False
    if status == True and "result" not in obdict:
        return False
    if status == False and "error" not in obdict:
        return False
    return True

### logging ###
def logcheck(ret, level = logging.DEBUG):
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

def inp_passw_cmd(msg, requester=""):
    if requester != "":
        inp = getpass(msg+" (from {}):\n".format(requester))
    else:
        inp = getpass(msg+":\n")
    return inp
pwcallmethodinst=inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg, requester=""):
    return pwcallmethodinst(msg, requester)

def notify_cmd(msg, requester):
    if requester != "":
        inp = input(msg+" (from {}): ".format(requester))
    else:
        inp = input(msg+": ")
    if inp.lower() in ["y", "j"]:
        return True
    elif inp.lower() in ["n"]:
        return False
    else:
        return None

notifyinst = notify_cmd

# returns True, False, None
def notify(msg, requester=""):
    return notifyinst(msg, requester)

##### init ######

def generate_certs(_path):
    _passphrase = pwcallmethod("(optional) Enter passphrase for encrypting key")
    if _passphrase is not None and isinstance(_passphrase, str) == False:
        logging.error("passphrase not str, None")
        return False
    if _passphrase != "":
        _passphrase2 = pwcallmethod("Retype:\n")
        if _passphrase != _passphrase2:
            return False
        if isinstance(_passphrase, str):
            _passphrase = bytes(_passphrase, "utf-8")
    _key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
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
    subject_name = _tname, 
    public_key = _pub_key, 
    serial_number = 0, 
    not_valid_before = datetime.date.today() - datetime.timedelta(days=2), 
    not_valid_after = datetime.date.today() + datetime.timedelta(days=200*365), 
    extensions = extensions)
    
    cert = builder.sign(_key, cert_sign_hash, default_backend())
    if _passphrase == "":
        encryption_algorithm = serialization.NoEncryption()
    else:
        encryption_algorithm = serialization.BestAvailableEncryption(_passphrase)
    privkey = _key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm = encryption_algorithm)
    pubcert = cert.public_bytes(serialization.Encoding.PEM)
    with open("{}.priv".format(_path), 'wb') as writeout:
        writeout.write(privkey)
    with open("{}.pub".format(_path), 'wb') as writeout:
        writeout.write(pubcert)
    return True

def check_certs(_path):
    privpath = "{}.priv".format(_path)
    pubpath = "{}.pub".format(_path)
    if os.path.exists(privpath) == False or os.path.exists(pubpath) == False:
        return False
    try:
        _context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        _context.load_cert_chain(pubpath, keyfile=privpath, password=lambda : bytes(pwcallmethod("Enter passphrase for decrypting privatekey:"), "utf-8"))
        return True
    except Exception as e:
        logging.error(e)
    return False

def init_config_folder(_dir, prefix):
    if os.path.exists(_dir) == False:
        os.makedirs(_dir, 0o700)
    else:
        os.chmod(_dir, 0o700)
    if os.path.exists(os.path.join(_dir, "broken")) == False:
        os.makedirs(os.path.join(_dir, "broken"), 0o700)
    else:
        os.chmod(os.path.join(_dir, "broken"), 0o700)
    _path = os.path.join(_dir, prefix)
    if os.path.exists("{}_name.txt".format(_path)) == False:
        _name = os.getenv("USERNAME")
        if _name is None:
            _name = os.getenv("USER")
        if _name is None:
            _name = os.getenv("HOME")
            if _name:
                _name = os.path.basename(_name)
        if _name is None:
            try:
                _name = socket.gethostname()
            except Exception:
                pass
        with open("{}_name.txt".format(_path), "w") as writeo:
            if prefix == "client":
                writeo.write("{}/{}".format(normalize_name(_name), 0))
            else:
                writeo.write("{}/{}".format(normalize_name(_name), server_port))
    if os.path.exists(_path+"_message.txt") == False:
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
    if os.path.isdir(path) == True:
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(cafile=path)
    return sslcont


re_parse_url_old = re.compile("\\[?(.*)\\]?:([0-9]+)")
re_parse_url = re.compile("(.*)-([0-9]+)$")
def scnparse_url(url, force_port = False):
    if isinstance(url, str) ==False:
        raise(AddressFail)
    if url == "":
        raise(AddressEmptyFail)
    _urlre = re.match(re_parse_url, url)
    if _urlre is not None:
        return _urlre.groups()[0], int(_urlre.groups()[1])
    if force_port == False:
        return (url, server_port)
    raise(EnforcedPortFail)


authrequest_struct = {
"algo": None,
"nonce": None,
"timestamp": None,
"realm": None
}

auth_struct = {
"auth": None, 
"timestamp": None
}

class scnauth_server(object):
    request_expire_time = None # in secs
    # auth realms
    realms = None
    hash_algorithm = None
    serverpubcert_hash = None
    
    def __init__(self, serverpubcert_hash, hash_algorithm=DEFAULT_HASHALGORITHM, request_expire_time=auth_request_expire_time):
        self.realms = {}
        self.hash_algorithm = hash_algorithm
        self.serverpubcert_hash = serverpubcert_hash
        self.request_expire_time = request_expire_time

    def request_auth(self, realm):
        if realm not in self.realms:
            logging.error("Not a valid realm: {}".format(realm))
        rauth = authrequest_struct.copy()
        rauth["algo"] = self.hash_algorithm
        # send server time, client time should not be used because timeouts are on serverside
        rauth["timestamp"] = str(int(time.time()))
        rauth["realm"] = realm
        rauth["nonce"] = self.realms[realm][1]
        return rauth

    def verify(self, realm, authdict):
        if realm not in self.realms or self.realms[realm] is None:
            return True
        if isinstance(authdict, dict) == False:
            logging.warning("authdict is no dict")
            return False
        if realm not in authdict:
            #always the case if getting pwrequest
            if len(authdict) > 0:
                logging.debug("realm not in transmitted authdict")
            return False
        if isinstance(authdict[realm], dict) == False:
            logging.warning("authdicts realm is no dict")
            return False
        
        if isinstance(authdict[realm].get("timestamp", None),str) == False:
            logging.warning("no timestamp")
            return False
        
        if authdict[realm].get("timestamp","").isdecimal() == False:
            logging.warning("Timestamp not a number")
            return False
        timestamp = int(authdict[realm].get("timestamp"))
        if timestamp < int(time.time())-self.request_expire_time:
            return False
        if dhash(authdict[realm].get("timestamp"), self.hash_algorithm, prehash=self.realms[realm][0]) == authdict[realm]["auth"]:
            return True
        return False

    def init_realm(self,realm, pwhash):
        # internal salt for memory protection+nonce
        nonce = os.urandom(salt_size).hex()
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

    def saveauth(self, pw, saveid, realm, algo=DEFAULT_HASHALGORITHM):
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

        
class http_server(socketserver.ThreadingMixIn,HTTPServer):
    """ server part of client/server """
    sslcont = None
    rawsock = None
    
    def __init__(self, _address, certfpath, _handler, pwmsg):
        self.address_family = socket.AF_INET6
        HTTPServer.__init__(self, _address, _handler, False)
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            # python for windows has disabled it
            # hope that it works without
            pass
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv", lambda:bytes(pwcallmethod(pwmsg), "utf-8"))
        self.socket = self.sslcont.wrap_socket(self.socket)
    #def get_request(self):
    #    if self.socket is None:
    #        return None, None
    #    socketserver.TCPServer.get_request(self)


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
    construct = struct.pack(addrstrformat, _contupel[1], len(binaddr),binaddr)
    for elem in range(0,3):
        _udpsock.sendto(construct, _dstaddrtupel)

class traverser_dropper(object):
    _srcaddrtupel = None
    #autoblacklist = None
    _sock = None
    active = True
    _checker = None
    def __init__(self, _srcaddrtupel):
        self._checker = threading.Condition()
        #self.autoblacklist = {}
        #if ":" in _srcaddrtupel[0]:
        #_socktype = socket.AF_INET6
        #else:
        #    _socktype = socket.AF_INET
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
        for elem in range(0,3):
            self._sock.sendto(construct, _dsttupel)
        if timeout:
            return self.check(timeout)
        else:
            return True
    
    def send_thread(self, _dsttupel, _contupel):
        self.send(_dsttupel, _contupel, None)


class traverser_helper(object):
    desttupels = []
    active = True
    mutex = None
    def __init__(self, connectsock, srcsock, interval=ping_interval):
        self.interval = interval
        self.connectsock = connectsock
        self.srcsock = srcsock
        self.mutex = threading.Lock()
        t = threading.Thread(target=self._connecter, daemon=True)
        t.start()
    
    
    def add_desttupel(self, destaddrtupel):
        ipaddresstype = None
        try:
            ipaddresstype = ipaddress.ip_address(destaddrtupel[0])
        except Exception:
            pass
        if self.connectsock.family == socket.AF_INET6 and isinstance(ipaddresstype,ipaddress.IPv4Address):
            destaddrtupel= ("::ffff:{}".format(destaddrtupel[0]),destaddrtupel[1])
        self.mutex.acquire()
        if destaddrtupel in self.desttupels:
            return True
        self.desttupels.append(destaddrtupel)
        self.mutex.release()
        t = threading.Thread(target=self._pinger, args=(destaddrtupel,), daemon=True)
        t.start()
        return True
    
    def del_desttupel(self, destaddrtupel):
        ipaddresstype = None
        try:
            ipaddresstype = ipaddress.ip_address(destaddrtupel[0])
        except Exception:
            pass
        if self.connectsock.family == socket.AF_INET6 and isinstance(ipaddresstype,ipaddress.IPv4Address):
            destaddrtupel= ("::ffff:{}".format(destaddrtupel[0]),destaddrtupel[1])
        self.mutex.acquire()
        try:
            self.desttupels.remove(destaddrtupel)
        except Exception:
            pass
        self.mutex.release()
        return True

    # makes client reachable by server by (just by udp?)
    def _pinger(self, _destaddrtupel):
        try:
            while self.active:
                self.mutex.acquire()
                if _destaddrtupel not in self.desttupels:
                    self.mutex.release()
                    break
                self.mutex.release()
                self.srcsock.sendto(scn_pingstruct, _destaddrtupel)
                time.sleep(self.interval)
        except Exception as e:
            logging.info(e)
        self.mutex.acquire()
        try:
            self.desttupels.remove(_destaddrtupel)
        except Exception:
            pass
        self.mutex.release()
    
    # sub __init__ thread
    def _connecter(self):
        while self.active:
            try:
                recv = self.srcsock.recv(512)
                if len(recv)!=512:
                    # drop invalid packages
                    continue
                unpstru = struct.unpack(addrstrformat, recv)
                port = unpstru[0]
                addr = unpstru[2][:unpstru[1]]
                try:
                    if self.connectsock.family == socket.AF_INET6 and ":" not in addr:
                        addr = "::ffff:{}".format(addr)
                    self._sock.connect((addr, port))
                    self._sock.sendto(scn_yesstruct, self._destaddrtupel)
                except Exception as e:
                    self._sock.sendto(scn_nostruct, self._destaddrtupel)
                    logging.info(e)

            except Exception as e:
                logging.info(e)



cert_update_header = \
{
"User-Agent": "simplescn/1.0 (update-cert)",
"Authorization": 'scn {}', 
"Connection": 'keep-alive'
}

# 
def check_updated_certs(_address, _port, certhashlist, newhash=None, timeout=None):
    update_list = []
    if None in [_address, _port]:
        logging.info("address or port empty")
        return None
    cont = default_sslcont()
    con = HTTPSConnection(_address, _port, timeout=timeout, context=cont)
    con.connect()
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
        #con.sock.do_handshake()
        ret = con.getresponse()
        if ret.status != 200:
            logging.info("checking cert failed, code: {}, reason: {}".format(ret.status, ret.reason))
            continue
        if con.sock and oldhash != dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()):
            logging.error("certificateexchange detected, stop checking ")
            break
        if dhash(brokensslcert) == _hash:
            update_list.append((_hash, _security))
        
    con.close()
    return update_list


class commonscn(object):
    capabilities = []
    info = None
    priority = None
    name = None
    message = None
    cert_hash = None
    scn_type = "unknown"
    pluginmanager = None
    isactive = True
    update_cache_lock = None
    
    cache={"cap":"", "info":"", "prioty":""}
    
    def __init__(self):
        self.update_cache_lock = threading.Lock()
    def __del__(self):
        self.isactive = False
    
    def update_cache(self):
        with self.update_cache_lock:
            self.cache["cap"] = json.dumps(gen_result({"caps": self.capabilities}, True))
            self.cache["info"] = json.dumps(gen_result({"type": self.scn_type, "name": self.name, "message":self.message}, True))
            self.cache["prioty"] = json.dumps(gen_result({"priority": self.priority, "type": self.scn_type}, True))

class commonscnhandler(BaseHTTPRequestHandler):
    links = None
    sys_version = "" # would say python xy, no need and maybe security hole
    auth_info = None
    statics = {}
    client_cert = None
    client_cert_hash = None
    alreadyrewrapped = False
    
    
    def scn_send_answer(self, status, body=None, mime="application/json", message=None, docache=False, dokeepalive=None):
        if message:
            self.send_response(status, message)
        else:
            self.send_response(status)
        
        if body:
            self.send_header("Content-Length", len(body))
        if mime and body:
            self.send_header("Content-Type", "{}; charset=utf-8".format(mime))
        if self.headers.get("X-certrewrap") is not None:
            self.send_header("X-certrewrap", self.headers.get("X-certrewrap").split(";")[1])
        if docache == False:
            self.send_header("Cache-Control", "no-cache")
            if dokeepalive is None and status == 200:
                dokeepalive = True
        if dokeepalive:
            self.send_header('Connection', 'keep-alive')
        self.end_headers()
        if body:
            self.wfile.write(body)
    
    # use cache?
    #htmlcache = {}
    def html(self, page, lang="en"):
        if self.webgui == False:
            self.send_error(404, "no webgui")
            return
        _ppath = os.path.join(sharedir, "html", lang, page)
        try:
            with open(_ppath, "r") as rob:
                fullob = rob.read()
                try:
                    _temp = self.links["client"].show({})[1]
                    _temp.update(self.links["client"].info({})[1])
                    fullob = fullob.format(**_temp)
                except KeyError:
                    pass
                self.scn_send_answer(200, body=bytes(fullob, "utf-8"), mime="text/html", docache=True)
        except FileNotFoundError:
            self.send_error(404, "file not found")
            
    def init_scn_stuff(self):
        useragent = self.headers.get("User-Agent", "")
        logging.debug("Useragent: {}".format(useragent))
        if "simplescn" in useragent:
            self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth= _auth.strip().rstrip()
        if method == "scn":
            # is different from the body, so don't use header information
            self.auth_info = safe_mdecode(_auth, "application/json; charset=utf-8") 
        else:
            self.auth_info = None
        
        if self.client_address[0][:7] == "::ffff:":
            self.client_address2 = (self.client_address[0][7:], self.client_address[1])
        else:
            self.client_address2 = (self.client_address[0], self.client_address[1])
        
        # hack around not transmitted client cert
        _rewrapcert = self.headers.get("X-certrewrap")
        _origcert = self.headers.get("X-original_cert")
        if _rewrapcert is not None:
            cont = self.connection.context
            if self.alreadyrewrapped == False:
                # wrap tcp socket, not ssl socket
                self.connection = self.connection.unwrap()
                self.connection = cont.wrap_socket(self.connection, server_side=False)
                self.alreadyrewrapped = True
            self.client_cert = ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True)).strip().rstrip()
            self.client_cert_hash = dhash(self.client_cert)
            if _rewrapcert.split(";")[0] != self.client_cert_hash:
                return False
            if _origcert and self.links.get("trusted_certhash", "") != "":
                if _rewrapcert == self.links.get("trusted_certhash"):
                    self.client_cert = _origcert
                    self.client_cert_hash = dhash(_origcert)
                else:
                    logging.debug("rewrapcert incorrect")
                    return False
            #self.rfile.close()
            #self.wfile.close()
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
        else:
            self.client_cert = None
            self.client_cert_hash = None
        return True
    
    def cleanup_stale_data(self, maxchars=max_serverrequest_size):
        if self.headers.get("Content-Length", "").strip().rstrip().isdecimal() == True:
            # protect against big transmissions
            self.rfile.read(min(maxchars, int(self.headers.get("Content-Length"))))
    
    def parse_body(self, maxlength=None):
        if self.headers.get("Content-Length", "").strip().rstrip().isdecimal() == False:
            self.scn_send_answer(411, message="POST data+data length needed")
            return None
        
        contsize = int(self.headers.get("Content-Length"))
        if maxlength and contsize > maxlength:
            self.scn_send_answer(431, message="request too large", docache=False)
        readob = self.rfile.read(contsize)
        # str: charset (like utf-8), safe_mdecode: transform arguments to dict
        obdict = safe_mdecode(readob, self.headers.get("Content-Type"))
        if obdict is None:
            self.scn_send_answer(400, message="bad arguments")
            return None
        obdict["clientaddress"] = self.client_address2
        obdict["clientcert"] = self.client_cert
        obdict["clientcerthash"] = self.client_cert_hash
        obdict["headers"] = self.headers
        obdict["socket"] = self.connection
        return obdict
    
    def handle_usebroken(self, sub):
        # invalidate as attacker can connect while switching
        self.alreadyrewrapped = False
        self.client_cert = None
        self.client_cert_hash = None
        certfpath = os.path.join(self.links["config_root"], "broken", sub)
        if os.path.isfile(certfpath+".pub") and os.path.isfile(certfpath+".priv"):
            cont = default_sslcont()
            cont.load_cert_chain(certfpath+".pub", certfpath+".priv")
            oldsslcont = self.connection.context

            self.connection = self.connection.unwrap()
            self.connection = cont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            
            self.scn_send_answer(200, message="brokencert successfull", docache=False, dokeepalive=True)
        else:
            oldsslcont = self.connection.context

            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            self.scn_send_answer(404, message="brokencert not found", docache=False, dokeepalive=True)
    
    def handle_plugin(self, func, action):
        self.send_response(200)
        self.send_header("Connection", "keep-alive")
        self.send_header("Cache-Control", "no-cache")
        if self.headers.get("X-certrewrap") is not None:
            self.send_header("X-certrewrap", self.headers.get("X-certrewrap").split(";")[1])
        self.end_headers()
        # send if not sent already
        self.wfile.flush()
        try:
            return func(action, self.connection, self.client_cert, self.client_cert_hash)
        except Exception as e:
            logging.error(e)
            return False

def create_certhashheader(certhash):
    _random = os.urandom(token_size).hex()
    return "{};{}".format(certhash, _random), _random


def dhash(oblist, algo=DEFAULT_HASHALGORITHM, prehash=""):
    if algo not in algorithms_strong:
        logging.error("Hashalgorithm not available: {}".format(algo))
        return None
    if isinstance(oblist, (list, tuple))==False:
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
            logging.error("Object not hash compatible: {}".format(ob))
            continue
        ret = tmp.hexdigest()
    return ret

# signals that method not be accessed by plugins (access_safe)
def classify_noplugin(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("noplugin")
    return func

# signals that method needs admin permission
def classify_admin(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("admin")
    return func
# signals that method only access internal methods and send no requests (e.g. do_request)
def classify_local(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("local")
    return func


# signals that method should have no pwcheck
# redirect overrides handle_local, handle_remote
def classify_redirect(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("redirect")
    return func

# signals that method is experimental
def classify_experimental(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("experimental")
    return func

# signals that method is insecure
def classify_insecure(func):
    if hasattr(func, "classify") == False:
        func.classify = set()
    func.classify.add("insecure")
    return func

# signals that method is access method
#access = accessing client/server
def classify_access(func):
    if hasattr(func, "classify") == False:
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
def check_args(_moddict, requires={}, optional={}, error=[]):
    search = set()
    if isinstance(requires,dict) == False:
        raise(TypeError("requires wrong type: "+type(requires).__name__))
    
    if isinstance(optional,dict) == False:
        raise(TypeError("optional wrong type: "+type(optional).__name__))
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
        error.append("wrong type: {}, {}".format(type(_moddict[argname]).__name__,_moddict[argname]))
        return False
    return True

# args is iterable with (argname, type)
# obdict (=_moddict) is modified
def check_argsdeco(requires={}, optional={}):
    def func_to_check(func):
        def get_args(*args):
            if len(args)!=2:
                logging.error("check_args: wrong function call: {}: {}".format(func.__name__, args))
            #    return False, "check_args failed ({}) wrong amount args: {}".format(func.__name__, args), isself, self.cert_hash
            self, obdict = args
            error = []
            if check_args(obdict, requires, optional, error=error) == False:
                return False, "check_args failed ({}) arg: {}, reason:{}".format(func.__name__, *error), isself, self.cert_hash
            resp = func(self, obdict)
            if resp is None:
                return False, "bug: no return value in function {}".format(type(func).__name__), isself, self.cert_hash
            if isinstance(resp, bool) == True or len(resp)==1:
                if isinstance(resp, bool) == False:
                    resp = resp[0]
                if resp == True:
                    return True, "{} finished successfully".format(func.__name__), isself, self.cert_hash
                else:
                    return False, "{} failed".format(func.__name__), isself, self.cert_hash
            elif len(resp)==2:
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
        raise(TypeError("invalid loglevel"))
    else:
        return int(loglevel)

def safe_mdecode(inp, encoding, charset="utf-8"):
    try:
        splitted = encoding.split(";",1)
        enctype = splitted[0].strip().rstrip()
        if isinstance(inp, str):
            string = inp
        elif isinstance(inp, bytes):
            if len(splitted)==2:
                #splitted in format charset=utf-8
                split2 = splitted[1].split("=")
                charset = split2[1].strip().rstrip()
            string = str(inp,charset)
        else:
            logging.error("Invalid type: {}".format(type(inp)))
            return
        if string == "":
            logging.info("Input empty")
            return None
        if enctype == "application/json":
            return json.loads(string)
        elif enctype == "application/x-www-form-urlencoded":
            obdict = parse.parse_qs(string)
            # json object encoded as string is parsed
            if obdict.get("jauth") is not None:
                obdict["auth"] = json.loads(obdict.get("jauth")[0])
            # fix limitation of parse_qs, "realm:pw" are splitted into dict format needed
            elif obdict.get("auth") is not None:
                oldauth = obdict["auth"].copy()
                obdict["auth"] = {}
                for elem in oldauth:
                    # splitted = realm, pw
                    splitted = elem.split(":", 1)
                    if len(splitted)==2:
                        obdict["auth"][splitted[0]] = splitted[1]
            return obdict
        else:
            logging.error("invalid parsing type: {}".format(enctype))
            return None
    except LookupError as e:
        logging.error("charset not available")
        return None
    except Exception as e:
        logging.error(e)
        return None

def check_reference(_reference):
    if _reference is None:
        return False
    if len(_reference) > 100:
        return False
    if all(c not in "\0'\"\x1A\x7F" for c in _reference) == False:
        return False
    return True

def check_reference_type(_reference_type):
    if _reference_type is None:
        return False
    if len(_reference_type) > 15:
        return False
    if all(c in "0123456789abcdefghijklmnopqrstuvxyz_" for c in _reference_type) == False:
        return False
    return True

def check_security(_security):
    if _security in security_states:
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
    if all(c in "0123456789abcdef" for c in hashstr) == False:
        return False
    return True

badnamechars = " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/"
# no .:[]to differ name from ip address
badnamechars += ".:[]"

def normalize_name(_name, maxlength=max_namelength):
    if _name is None:
        return None
    # name shouldn't be too long or ""
    _name = _name[:maxlength]
    if len(_name)==0:
        _name = "empty"
        return _name
    _oldname = _name
    _name = ""
    for c in _oldname:
        # ensure no bad, control characters
        if c in badnamechars or c.isprintable() == False:
            pass
        else:
            _name += c
    #name shouldn't be isself as it is used 
    if _name == isself:
        _name = "fake_"+isself
    return _name

def check_name(_name, maxlength=max_namelength):
    if _name is None:
        return False
    # name shouldn't be too long or 0
    if len(_name) > maxlength or len(_name) == 0:
        return False
    for c in _name:
        # ensure no bad, control characters
        if c in badnamechars or c.isprintable() == False:
            return False
    #name shouldn't be isself as it is used 
    if _name == isself:
        return False
    return True

def check_typename(_type, maxlength = max_typelength):
    if _type is None:
        return False
    # type shouldn't be too long or 0
    if len(_type) > maxlength or len(_type) == 0:
        return False
    # ensure no bad characters
    if _type.isalpha() == False:
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
    except Exception as e:
        logging.error("invalid value converter: {} value: {} error: {}".format(_converter, _value, e))
        return False
    return True

def rw_socket(sockr, sockw):
    while True:
        if bool(sockr.getsockopt(socket.SO_TCP_CLOSE)) == False and \
           bool(sockr.getsockopt(socket.SO_TCP_CLOSING)) == False:
            sockw.close()
            break
        if bool(sockw.getsockopt(socket.SO_TCP_CLOSE)) == False and \
           bool(sockw.getsockopt(socket.SO_TCP_CLOSING)) == False:
            sockr.close()
            break
        try:
            sockw.sendall(sockr.read(default_buffer_size))
        except socket.timeout:
            sockw.close()
            break
        except Exception as e:
            logging.error(e)
            break

