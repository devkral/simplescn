#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

import os, sys

sharedir = os.path.dirname(os.path.realpath(__file__))
# append to pathes
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

#if platform.python_implementation()=="PyPy":
#    sys.path+=['', '/usr/lib/python34.zip', '/usr/lib/python3.4', '/usr/lib/python3.4/plat-linux', '/usr/lib/python3.4/lib-dynload', '/usr/lib/python3.4/site-packages', '/usr/lib/site-python']

import ipaddress
from getpass import getpass

import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID #,ExtendedKeyUsageOID
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
import base64
from urllib import parse
from http.client import HTTPSConnection 
from http.server import HTTPServer
import socketserver

## sizes ##
salt_size = 10
token_size = 10
key_size = 4096
# size of chunks (only in use by rw_socket?)
default_buffer_size = 1400
max_serverrequest_size = 4000
# maybe a bad idea to change
max_typelength = 15
max_namelength = 64

## timeouts ##
# time out for auth requests
auth_request_expire_time = 60*3
ping_interval = 50

## activate experimental functions (maybe insecure) ##
experimental = False

## file positions ##
default_configdir = '~/.simplescn/'
confdb_ending = ".confdb"
# don't change
isself = 'isself'
pluginstartfile = "main.py"

## ports ##
client_port = 0
server_port = 4040

## hash algorithms ##
algorithms_strong = ['sha512', 'sha384', 'sha256', 'whirlpool']
cert_sign_hash = hashes.SHA512()
# don't change
DEFAULT_HASHALGORITHM = "sha256"
DEFAULT_HASHALGORITHM_len = 64

## server only ##

# loads: min_items, refresh, expire
high_load = (100000, 10*60, 2*60*60)
medium_load = (1000, 60, 4*60*60)
low_load = (500, 10, 4*60*60)
# special load just: refresh, expire
very_low_load = (1, 24*60*60)

## defaults (most probably no change needed) ##
default_priority = 20
default_timeout = 60



###### signaling ######
security_states = ["compromised", "old", "valid", "insecure"]

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




#### logging ####

class scn_logger(logging.Logger):
    _defaultHandler = None
    lformat = None

    def __init__(self, _handler = logging.StreamHandler()):
        logging.Logger.__init__(self, "scn_logger")
        _handler.setFormatter(logging.Formatter('%(levelname)s::%(filename)s:%(lineno)d::%(funcName)s::%(message)s'))
        self.replaceHandler(_handler)
        
    def replaceHandler(self, newhandler):
        if self._defaultHandler is not None:
            self.removeHandler(self._defaultHandler)
        self.addHandler(newhandler)
        self._defaultHandler = newhandler
        
        
    def check(self, ret, level = logging.DEBUG):
        if ret[0]==True:
            return True
        else:
            if level != 0:
                #use of internal function
                self._log(level, ret[1], ())
            return False


#global loggerinst
loggerinst = None

def logger():
    global loggerinst
    return loggerinst

def init_logger(_logger = scn_logger()):
    global loggerinst
    if loggerinst is None:
        loggerinst = _logger


#def replace_logger(_logger):
#    global loggerinst
#    loggerinst = _logger



def inp_passw_cmd(msg, requester=None):
    if requester:
        inp = getpass(msg+" (from {}):\n".format(requester))
    else:
        inp = getpass(msg+":\n")
    return inp
pwcallmethodinst=inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg, requester=None):
    return pwcallmethodinst(msg, requester)

def notify_cmd(msg, requester):
    if requester:
        inp = input(msg+" (from {}): ".format(requester))
    else:
        inp = getpass(msg+": ")
    if inp.lower() in ["y", "j"]:
        return True
    elif inp.lower() in ["n"]:
        return False
    else:
        return None
        
notifyinst = notify_cmd

# returns True, False, None
def notify(msg, requester=None):
    return notifyinst(msg, requester)



##### init ######

def generate_certs(_path):
    _passphrase = pwcallmethod("(optional) Enter passphrase for encrypting key:")
    if _passphrase is not None and isinstance(_passphrase, str) == False:
        logger().error("passphrase not str, None")
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
    
    #extendedext = x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH, 
    #ExtendedKeyUsageOID.CLIENT_AUTH))
    
    extensions = []#x509.Extension(extendedext.oid, True, extendedext)]
    
    builder = x509.CertificateBuilder(issuer_name=_tname, 
    subject_name = _tname, 
    public_key = _pub_key, 
    serial_number = 0, 
    not_valid_before = datetime.date.today() - datetime.timedelta(days=2), 
    not_valid_after = datetime.date.today() + datetime.timedelta(days=200*365), 
    extensions = extensions)
    # builder = builder.add_extension(extendedext, critical=True) # = extensions
    
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
        logger().error(e)
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
        with open("{}_name.txt".format(_path), "w") as writeo:
            if prefix == "client":
                writeo.write("{}/{}".format(normalize_name(os.getenv("USERNAME")), 0))
            else:
                writeo.write("{}/{}".format(normalize_name(os.getenv("USERNAME")), server_port))
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
    if os.path.isdir(path) == True: #if dir, then capath, if file then cafile
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(cafile=path)
    return sslcont


re_parse_url_old = re.compile("\\[?(.*)\\]?:([0-9]+)")
re_parse_url = re.compile("(.*)-([0-9]+)$")
#re_parse_url_no_port = re.compile("([0-9:.]+[0-9]+)")
def scnparse_url(url, force_port = False):
    if isinstance(url, str) ==False:
        raise(AddressFail)
    if url == "":
        raise(AddressEmptyFail)
    _urlre = re.match(re_parse_url, url)
    if _urlre is not None:
        return _urlre.groups()[0], int(_urlre.groups()[1])
    #_urlre = re.match(re_parse_url_no_port, url)
    #if _urlre is None:
    #    raise(AddressInvalidFail)
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
            logger().error("Not a valid realm: {}".format(realm))
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
        if realm not in authdict:
            logger().debug("realm not in authdict")
            return False
        if isinstance(authdict[realm], dict) == False:
            logger().debug("realm is no dict")
            return False
        
        if isinstance(authdict[realm].get("timestamp", None),str) == False:
            logger().error("no timestamp")
            return False
        
        if authdict[realm].get("timestamp","").isdecimal() == False:
            logger().error("Timestamp not a number")
            return False
        timestamp = int(authdict[realm].get("timestamp"))
        if timestamp < int(time.time())-self.request_expire_time:
            return False
        if dhash(authdict[realm].get("timestamp"), self.hash_algorithm, prehash=self.realms[realm][0]) == authdict[realm]["auth"]:
            return True
        return False

    def init_realm(self,realm, pwhash):
        # internal salt for memory protection+nonce
        nonce = str(base64.urlsafe_b64encode(os.urandom(salt_size)), "utf-8")
        self.realms[realm] = (dhash((pwhash, realm, nonce, self.serverpubcert_hash), self.hash_algorithm), nonce)


class scnauth_client(object):
    # save credentials
    save_auth = None
    
    def __init__(self):
        self.save_auth = {}
    
    def auth(self, pw, authreq_ob, serverpubcert_hash, savedata=None):
        realm = authreq_ob["realm"]
        pre = dhash((dhash(pw, authreq_ob["algo"]), authreq_ob["realm"]), authreq_ob["algo"])
        if savedata != None:
            saveid = savedata 
            if saveid not in self.save_auth:
                self.save_auth[saveid] = {}
            self.save_auth[saveid][realm] = (pre, authreq_ob["algo"])
        return self.asauth(pre, authreq_ob, serverpubcert_hash)
    
    def asauth(self, pre, authreq_ob, pubcert_hash):
        if pre is None:
            return None
        dauth = auth_struct.copy()
        dauth["timestamp"] = authreq_ob["timestamp"]
        dauth["auth"] = dhash((authreq_ob["nonce"], pubcert_hash, authreq_ob["timestamp"]), authreq_ob["algo"], prehash=pre)
        return dauth

    def saveauth(self, realm, pw, savedata, algo=DEFAULT_HASHALGORITHM):
        saveid = savedata
        pre = dhash((dhash(pw, algo), realm), algo)
        if saveid not in self.save_auth:
            self.save_auth[saveid] = {}
        self.save_auth[saveid][realm] = (pre, algo)

    def reauth(self, savedata, authreq_ob, pubcert_hash):
        saveid = savedata
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
        self.rawsock = self.socket
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
            logger().info(e)
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
                    logger().info(e)

            except Exception as e:
                logger().info(e)



cert_update_header = \
{
"User-Agent": "simplescn/0.5 (update-cert)",
"Authorization": 'scn {}', 
"Connection": 'keep-alive'
}

# 
def check_updated_certs(_address, _port, certhashlist, newhash=None, timeout=None):
    update_list = []
    if None in [_address, _port]:
        logger().info("address or port empty")
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
            logger().info("checking cert failed, code: {}, reason: {}".format(ret.status, ret.reason))
            continue
        if con.sock and oldhash != dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()):
            logger().error("certificateexchange detected, stop checking ")
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

def create_certhashheader(certhash):
    _random = str(base64.urlsafe_b64encode(os.urandom(token_size)), "utf-8")
    return "{};{}".format(certhash, _random), _random


def dhash(oblist, algo=DEFAULT_HASHALGORITHM, prehash=""):
    if algo not in algorithms_strong:
        logger().error("Hashalgorithm not available: {}".format(algo))
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
            logger().error("Object not hash compatible: {}".format(ob))
            continue
        ret = tmp.hexdigest()
    return ret

# signals that method not be accessed by plugins
def classify_noplugin(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("noplugin")
    return func


# signals that method needs admin permission
def classify_admin(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("admin")
    return func
# signals that method only access internal methods and send no requests (e.g. do_request)
def classify_local(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("local")
    return func
    
# signals that method is experimental
def classify_experimental(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("experimental")
    return func

# signals that method is insecure
def classify_insecure(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("insecure")
    return func

# signals that method is access method
#access = accessing client/server
def classify_access(func):
    if hasattr(func, "classify") == False:
        func.classify=set()
    func.classify.add("access")
    return func

def gen_doc_deco(func):
    # skip when no documentation is available
    if func.__doc__ is None:
        return func
    
    if hasattr(func, "requires"):
        requires = func.requires
    else:
        requires = {}
    if hasattr(func, "optional"):
        optional = func.optional
    else:
        optional = {}
    
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

    spacing = " "*2
    sep = ",\n{spaces}  ".format(spaces=spacing)
    if hasattr(func, "classify"):
        classify = " ({})".format(", ".join(sorted(func.classify)))
    else:
        classify = ""
    newdoc = "{}{classify}: {}\n{spaces}return: {}\n".format(func.__name__, _docfunc, _docreturn, spaces=spacing, classify=classify)
    if len(requires) == 0:
        newdoc = "{}{spaces}requires: n.a.{sep}".format(newdoc, spaces=spacing, sep=sep)
    else:
        newdoc = "{}{spaces}requires:\n{spaces}  ".format(newdoc, spaces=spacing)
    for key in requires.keys():
        newdoc = "{}{}({}): {}{sep}".format(newdoc, key, requires[key].__name__, _docrequires.get(key, "n.a."), sep=sep)
    if len(optional) != 0:
        newdoc = "{}\n{spaces}optional:\n{spaces}  ".format(newdoc[:-len(sep)], spaces=spacing)
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
            error.append("no found")
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
# _moddic is modified
def check_argsdeco(requires={}, optional={}):
    def func_to_check(func):
        def get_args(*args):
            if len(args)!=2:
                logger().error("check_args: wrong function call: {}: {}".format(func.__name__, args))
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
        if hasattr(func, "classify"):
            get_args.classify = func.classify
        return gen_doc_deco(get_args)
    return func_to_check

def safe_mdecode(inp, encoding, charset="utf-8"):
    try:
        splitted=encoding.split(";",1)
        enctype=splitted[0].strip().rstrip()
        if isinstance(inp, dict) == True:
            logger().warning("already parsed")
            return None
        elif isinstance(inp, str) == True:
            string = inp
        else:
            if len(splitted)==2:
                #splitted in format charset=utf-8
                split2 = splitted[1].split("=")
                charset = split2[1].strip().rstrip()
            string = str(inp,charset)
        if string == "":
            logger().debug("Input empty")
            return None
        if enctype == "application/x-www-form-urlencoded":
            tparse=parse.parse_qs(string)
            if "auth" in tparse:
                authold = tparse.copy()
                authnew = {}
                for elem in authold:
                    splitted = elem.split(":", 1)
                    if len(splitted) == 1:
                        return False, "auth object invalid (<realm>:<pw>)"
                    realm,  pw = splitted
                    authnew[realm] = pw
                tparse["auth"] = authnew
            # auth needs to be json formatted
            if tparse.get("jauth", None) is not None:
                tparse["auth"] = json.loads(tparse.get("auth")[0])
            return tparse
        elif enctype == "application/json": 
            return json.loads(string)
        elif enctype in ["text/html", "text/plain"]:
            logger().warning("try to parse plain/html text")
            return None
        else:
            return None
    except LookupError as e:
        logger().error("charset not available")
        return None
    except Exception as e:
        logger().error(e)
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

def check_hash(_hashstr, _hashlen=None):
    if _hashstr is None:
        return False
    if _hashlen and len(_hashstr) != _hashlen: #DEFAULT_HASHALGORITHM_len:
        return False
    if all(c in "0123456789abcdefABCDEF" for c in _hashstr) == False:
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
        logger().error("invalid value converter:{} value:{} error:{}".format(_converter, _value, e))
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
            logger().error(e)
            break

