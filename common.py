#! /usr/bin/env python3

# preamble, recommended for portability
#import os, sys
#sharedir = None
#if "__file__" not in globals():
#    __file__ = sys.argv[0]
#
#if sharedir is None:
#    # use sys
#    sharedir = os.path.dirname(os.path.realpath(__file__))
#
## append to pathes
#if sharedir[-1] == os.sep:
#    sharedir = sharedir[:-1]
#if sharedir not in sys.path:
#    sys.path.append(sharedir)

# not preamble used by sharedir files
import os, sys
if "__file__" not in globals():
    __file__ = sys.argv[0]
sharedir = os.path.dirname(os.path.realpath(__file__))

# append to pathes
if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)


#if platform.python_implementation()=="PyPy":
#    sys.path+=['', '/usr/lib/python34.zip', '/usr/lib/python3.4', '/usr/lib/python3.4/plat-linux', '/usr/lib/python3.4/lib-dynload', '/usr/lib/python3.4/site-packages', '/usr/lib/site-python']

import importlib
# import extra
import importlib.machinery
from types import ModuleType # needed for ModuleType
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
import traceback

import hashlib
import re
import threading
import json
import base64
import time
from urllib import parse

## sizes ##
salt_size = 10
key_size = 4096
# size of chunks (only in use by rw_socket?)
default_buffer_size = 1400
max_serverrequest_size = 4000

## timeouts ##
# time out for auth requests
auth_request_expire_time = 60*3

## file positions ##
confdb_ending = ".confdb"
isself = 'isself'
default_configdir = '~/.simplescn/'

## ports ##
client_port = 0
server_port = 4040

## hash algorithms ##
algorithms_strong = ['sha512', 'sha384', 'sha256', 'whirlpool']
DEFAULT_HASHALGORITHM = "sha256"
DEFAULT_HASHALGORITHM_len = 64

cert_sign_hash = hashes.SHA512()

## server only ##

# loads: min_items, refresh, expire
high_load = (100000, 1*60*60, 2*60*60)
medium_load = (1000, 10*60, 4*60*60)
low_load = (500, 30, 4*60*60)
# special load just: refresh, expire
very_low_load = (10, 24*60*60)

## defaults (most probably no change needed) ##
default_priority = 20
default_timeout = 60



###### signaling ######


class AddressFail(Exception):
    msg = '"<address>[:<port>]": '
class EnforcedPortFail(AddressFail):
    msg = 'address is lacking ":<port>"'
class AddressEmptyFail(AddressFail):
    msg = '{} address is empty'.format(AddressFail.msg)

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
    if hasattr(err, "msg"):
        error["msg"] = str(err.msg)
    else:
        error["msg"] = str(err)
    if isinstance(err,str) == True:
        error["type"] = ""
    else:
        error["type"] = type(err).__name__
        if hasattr(err,"__traceback__"):
            error["stacktrace"] = str(traceback.format_tb(err.__traceback__)) 
        elif hasattr(sys,"last_traceback"):
            error["stacktrace"] = str(traceback.format_tb(sys.last_traceback)) 
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
        self.lformat = logging.Formatter('%(levelname)s::%(filename)s:%(lineno)d::%(funcName)s::%(message)s')
        _handler.setFormatter(self.lformat)
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



def inp_passw_cmd(msg):
    def func(*args):
        return getpass(msg+"\n")
    return func
pwcallmethodinst=inp_passw_cmd

# returns func which asks the user for the password with message
def pwcallmethod(msg):
    return pwcallmethodinst(msg)


def notify_cmd(msg):
    inp = input(msg)
    if inp.lower() in ["y", "j"]:
        return True
    elif inp.lower() in ["n",]:
        return False
    else:
        return None
        
notifyinst=notify_cmd

# returns True, False, None
def notify(msg):
    return notifyinst(msg)



##### init ######

def generate_certs(_path):
    _passphrase = pwcallmethod("(optional) Enter passphrase for encrypting key:")()
    if _passphrase != "":
        _passphrase2 = pwcallmethod("Retype:\n")()
        if _passphrase != _passphrase2:
            return False
    
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
        _context.load_cert_chain(pubpath, keyfile=privpath, password = pwcallmethod("Enter passphrase for decrypting privatekey:"))
        return True
    except Exception as e:
        logger().error(e)
    return False

def init_config_folder(_dir, prefix):
    if os.path.exists(_dir) == False:
        os.makedirs(_dir, 0o700)
    else:
        os.chmod(_dir, 0o700)
    _path = os.path.join(_dir, prefix)
    if os.path.exists("{}_name.txt".format(_path)) == False:
        e = open("{}_name.txt".format(_path), "w")
        if prefix == "client":
            e.write("{}/{}".format(normalize_name(os.uname()[1]), 0))
        else:
            e.write("{}/{}".format(normalize_name(os.uname()[1]), server_port))
        e.close()
    if os.path.exists(_path+"_message.txt") == False:
        e=open("{}_message.txt".format(_path), "w")
        e.write("<message>")
        e.close()

##### etc ######

#work around crappy python ssl implementation
#which doesn't allow reads from strings
def workaround_ssl(text_cert):
    import tempfile
    t = tempfile.NamedTemporaryFile()
    t.write(text_cert)
    return t

def default_sslcont():
    sslcont = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslcont.set_ciphers("HIGH")
    sslcont.options = sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
    return sslcont

def gen_sslcont(path):
    sslcont = default_sslcont()
    if os.path.isdir(path) == True: #if dir, then capath, if file then cafile
        sslcont.load_verify_locations(capath = path)
    else:
        sslcont.load_verify_locations(path)
    return sslcont




re_parse_url = re.compile("\\[?(.*)\\]?:([0-9]+)")
def scnparse_url(url, force_port = False):
    if isinstance(url, str) ==False:
        raise(AddressFail)
    if url == "":
        raise(AddressEmptyFail)
    _urlre = re.match(re_parse_url, url)
    if _urlre is not None:
        return _urlre.groups()
    elif force_port == False:
        return (url, server_port)
    raise(EnforcedPortFail)



class configmanager(object):
    db_path = None
    dbcon = None
    lock = None
    imported = False
    overlays = {}
    defaults = {"state":("False", bool, "is component active")}
    def __init__(self, _dbpath):
        self.db_path = _dbpath
        self.lock = threading.Lock()
        self.reload()

    def __del__(self):
        if self.dbcon is not None:
            self.dbcon.close()
        
    def __getitem__(self, _name):
        self.get(_name)
    
    def dbaccess(func):
        def funcwrap(self, *args, **kwargs):
            self.lock.acquire()
            temp = None
            try:
                temp = func(self, self.dbcon, *args, **kwargs)
            except Exception as e:
                if hasattr(e, "__traceback__"):
                    st = "{}\n\n{}".format(e, traceback.format_tb(e.__traceback__))
                else:
                    st = "{}".format(e)
                logger().error(st)
            self.lock.release()
            return temp
        return funcwrap

    def reload(self):
        if self.db_path is None:
            return
        if self.db_path is not None and self.imported == False:
            try:
                import sqlite3
                self.imported = True
            except ImportError as e:
                logger().error("import sqlite for user settings failed, reason:{}".format(e))
                self.db_path=None
        self.lock.acquire()
        if self.dbcon is not None:
            self.dbcon.close()
        self.dbcon = sqlite3.connect(self.db_path)
        cur = self.dbcon.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS main(name TEXT, val TEXT,PRIMARY KEY(name));''')
        # initialise with "False"
        cur.execute('''INSERT OR IGNORE INTO main(name,val) values ("state","False");''')
        self.dbcon.commit()
        self.lock.release()

    @dbaccess
    def update(self, dbcon, _defaults, _overlays = {}):
        # insert False, don't let it change
        _defaults["state"] = ("False", bool, "is component active")
        self.defaults = {}
        self.overlays = {}
        for _key, elem  in _defaults.items():
            tmp = None
            if len(elem) == 2:
                tmp = [elem[0], elem[1], ""]
            elif len(elem) == 3:
                tmp = list(elem)
            if tmp is None:
                logger().error("invalid default tuple: key:{} tuple:{}".format(_key, elem))
                return False
            if check_conftype(tmp[0], tmp[1]) == False:
                return False
            self.defaults[_key] = tmp
        
        for _key, elem  in _overlays.items():
            tmp = None
            if len(elem) == 1 or (len(elem) == 2 and elem[1] is None):
                if _key in self.defaults:
                    tmp = self.defaults[_key].copy()
                    tmp[0] = elem[0]
                else:
                    continue
            elif len(elem) == 2:
                tmp = [elem[0], elem[1], ""]
            elif len(elem) == 3:
                tmp = list(elem)
            if tmp is None:
                logger().error("invalid default tuple: key:{} tuple:{}".format(_key, elem))
                return False
            if _key in self.defaults:
                if tmp[1] != self.defaults[_key][1]:
                    logger().error("converter mismatch between defaults: {} and overlays: {}".format(self.defaults[_key][1], tmp[1]))
                    return False

            if check_conftype(tmp[0], tmp[1]) == False:
                return False
            self.overlays[_key] = tmp

        if dbcon is None:
            return True
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM main;''')
        _in_db = cur.fetchall()
        
        for _key, (_value, _type, _doc) in _defaults.items():
            cur.execute('''INSERT OR IGNORE INTO main(name,val) values (?,?);''', (_key, _value))
        if _in_db == None:
            return True
        for elem in _in_db:
            if elem[0] not in _defaults:
                cur.execute('''DELETE FROM main WHERE name=?;''', (elem[0],))
        dbcon.commit()
        return True
        
    @dbaccess
    def set(self, dbcon, name, value):
        if isinstance(name, str) == False:
            logger().error("name not string")
            return False
        if name in self.overlays and check_conftype(value, self.overlays[name][1]) == False:
            #logger().error("overlays value type missmatch")
            return False
        elif name in self.defaults and check_conftype(value, self.defaults[name][1]) == False:
            #logger().error("invalid defaults value type")
            return False
        elif name not in self.defaults and name not in self.overlays:
            logger().error("not in defaults/overlays")
            return False
        
        if value is None:
            value = ""
            
        """if isinstance(value, bool)==True:
            if value==True:
                value="true"
            else:
                value="false" """
        if name in self.overlays or dbcon is None:
            self.overlays[name][0] = str(value)
        elif dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''UPDATE main SET val=? WHERE name=?;''', (str(value), name))
            dbcon.commit()
        return True
    
    def set_default(self, name):
        if name not in self.defaults:
            return False
        return self.set(name, self.defaults[name][0])
    
    # get converted value
    @dbaccess
    def get(self, dbcon, _key):
        if isinstance(_key, str) == False:
            logger().error("key no string")
            return None
        
        # key can be in overlays but not in defaults
        if _key in self.overlays:
            ret = self.overlays[_key][0]
            _converter = self.overlays[_key][1]
        else:
            if _key not in self.defaults:
                logger().error("\"{}\" is no key".format(_key))
                return None
            _converter = self.defaults[_key][1]
            ret = self.defaults[_key][0]
            if dbcon is not None:
                cur = dbcon.cursor()
                cur.execute('''SELECT val FROM main WHERE name=?;''', (_key,))
                temp = cur.fetchone()
                if temp is not None and temp[0] is not None:
                    ret = temp[0]
                    
        
        if ret is None:
            return ""
        elif ret in ["False", "false", False]:
            return False
        elif ret in ["True", "true", True]:
            return True
        else:
            return _converter(ret)
    
    def getb(self, name):
        temp = self.get(name)
        if temp in [None, "-1", -1, "", False]:
            return False
        return True
    
    def get_default(self, name):
        if name in self.defaults:
            if self.defaults[name] is None:
                return ""
            else:
                return self.defaults[name][0]
        else:
            return None
    
    def get_meta(self, name):
        if name in self.overlays:
            return self.overlays[name][1:]
        elif name in self.defaults:
            return self.defaults[name][1:]
        else:
            return None
    
    @dbaccess
    def list(self, dbcon, onlypermanent=False):
        ret = []
        _tdic = self.defaults.copy()
        _tdic.update(self.overlays.copy())
        _listitems = sorted(_tdic.items(), key=lambda t: t[0])
        if dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''SELECT name, val FROM main;''')
            _in_db_list = cur.fetchall()
            _in_db = {}
            
            if _in_db_list is not None:
                for _key, _val in _in_db_list:
                    _in_db[_key] = _val
        
        for elem in _listitems:
            if len(elem) != 2 or len(elem[1]) != 3:
                logger().error("invalid element {}".format(elem))
                continue
            _key, (_defaultval, _converter, _doc) = elem
            _val2 = _defaultval
            ispermanent = True
            # ignore overlayentries with entry None
            if _key in self.overlays: # and self.overlays[_key] is not None:
                _val2 = self.overlays[_key][0]
                _converter, _doc = self.overlays[_key][1:]
                ispermanent = False
            elif _key in _in_db:
                _val2 = _in_db[_key]
                ispermanent = True
            if _val2 is None:
                _val2 = ""
            
            if _val2 in ["False", "false", False]:
                _val2 = "False"
            elif _val2 in ["True", "true", True]:
                _val2 = "True"
            else:
                if _converter is bool:
                    _val2 = bool(_val2)
                _val2 = str(_val2)
            if _key in ["state",] and _val2 in [None, "", "False"]:
                _val2 = "False"
            if onlypermanent == True and ispermanent == True:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
            elif onlypermanent == False:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
        return ret

def pluginressources_creater(_dict, requester):
    def wrap(res):
        ob = _dict.get(res)
        if ob is None:
            logger().error("Resource: {} not available".format(res))
            return None
        elif callable(ob) == True:
            def wrap2(*args, **kwargs):
                kwargs["requester"] = requester
                return ob(*args,**kwargs)
            return wrap2
        #elif hasattr(ob, "shared_with") and 
        else:
            return ob.copy()
    return wrap

class pluginmanager(object):
    pluginenv = None
    pathes_plugins = None
    path_plugins_config = None
    resources = None
    interfaces = []
    plugins = {}
    
    def __init__(self, _pathes_plugins, _path_plugins_config, scn_type, pluginenv = sys.path, resources = {}):
        self.pluginenv = pluginenv.copy()
        self.pathes_plugins = _pathes_plugins
        self.path_plugins_config = _path_plugins_config
        self.pluginenv = pluginenv
        self.resources = resources
        self.interfaces.append(scn_type)
        
    def list_plugins(self):
        temp = {}
        for path in self.pathes_plugins:
            if path in ["__pycache__", ""] or path[0] == " " or path[-1] == " ":
                continue
            if os.path.isdir(path) == True:
                for plugin in os.listdir(path):
                    temp[plugin] = path
        return temp
    
    def plugin_is_active(self, plugin):
        pconf = configmanager(os.path.join(self.path_plugins_config,"{}{}".format(plugin, confdb_ending)))
        return pconf.getb("state")
             
    
    def clean_plugin_config(self):
        lplugins = self.list_plugins()
        lconfig = os.listdir(self.path_plugins_config)
        for dbconf in lconfig:
            #remove .confdb
            if dbconf[:-len(confdb_ending)] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config, dbconf))
    
    def init_plugins(self):
        for plugin in self.list_plugins().items():
            pconf = configmanager(os.path.join(self.path_plugins_config,"{}{}".format(plugin[0], confdb_ending)))
            if pconf.getb("state") == False:
                continue
            # path is array with searchpathes
            pspec = importlib.machinery.PathFinder.find_spec(plugin[0],[plugin[1],])
            if pspec is None or pspec.loader is None:
                logger().info("Plugin \"{}\" not loaded\nPath: {}".format(plugin[0],plugin[1]))
                continue

            #init sys pathes
            newenv = self.pluginenv.copy()
            pluginpath = os.path.join(plugin[1], plugin[0])
            newenv.append(pluginpath)
            pspec.submodule_search_locations = newenv
            #load module
            if not hasattr(pspec.loader, 'exec_module'):
                pload = pspec.loader.load_module()
            else:
                pload = None
                if hasattr(pspec.loader, 'create_module'):
                    pload = pspec.loader.create_module(pspec)
                if pload is None:
                    pload = ModuleType(pspec.name)
                try:
                    pspec.loader.exec_module(pload)
                except Exception as e:
                    if "__traceback__" in e.__dict__:
                        st = "{}\n\n{}".format(e, traceback.format_tb(e.__traceback__))
                    else:
                        st = str(e)
                    logger().error("Plugin \"{}\":\n{}".format(plugin[0], st))
                    continue
            if "defaults" not in pload.__dict__ or \
                "init" not in pload.__dict__:
                continue
            try:
                # no changeable default
                pload.defaults["state"] = ("False", bool, "is plugin active")
            except Exception as e:
                logger().error("Plugin \"{}\":\ndefaults is a dict?:\n{}".format(plugin[0],e))
                continue
            pconf.update(pload.defaults)
            pload.config = pconf # no copy because it is the only user
            pload.resources = pluginressources_creater(self.resources, plugin[0]) # no copy because they can change
            pload.interfaces = self.interfaces.copy() # copy because of isolation
            pload.proot = pluginpath # no copy because it is the only user
            pload.module = pload
            ret = False
            # load plugin init method
            try:
                # use return False if plugin does not fit
                ret = pload.init()
            except Exception as e:
                if hasattr(e,"tb_frame"):
                    st = "{}\n\n{}".format(e, traceback.format_tb(e))
                else:
                    st = str(e)
                logger().error(st)
            # receive is a function to overload, it get connections from handler
            if ret == True:
                self.plugins[plugin[0]] = pload
            else:
                del pload # delete

    def register_remote(self, _addr):
        self.redirect_addr = _addr

    def delete_remote(self):
        self.redirect_addr = ""

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
            logger().warning("realm not in authdict")
            return False
        if isinstance(authdict[realm].get("timestamp"),str) == False:
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
            return authreq_ob.get("realm"), None
        if authreq_ob.get("realm") not in self.save_auth[saveid]:
            return authreq_ob.get("realm"), None
        return self.auth(self.save_auth[saveid][authreq_ob["realm"]], authreq_ob, pubcert_hash)


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
        if len(value) not in [1, 2]:
            raise(IndexError("len invalid: "+str(value)))
        _type = value[0]
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
                logger().error("check_args:wrong functioncall: {}: {}".format(func.__name__, args))
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
        return get_args
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
    if _security in ["compromised", "old", "valid"]:
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

def normalize_name(_name, maxlength=64):
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

def check_name(_name, maxlength=64):
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

def check_typename(_type, maxlength = 15):
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

class certhash_db(object):
    db_path = None
    lock = None

    def __init__(self,dbpath):
        import sqlite3
        self.db_path = dbpath
        self.lock = threading.Lock()
        try:
            con = sqlite3.connect(self.db_path)
        except Exception as e:
            logger().error(e)
            return
        self.lock.acquire()
        try:
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, security TEXT, certreferenceid INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
            con.execute('''CREATE TABLE if not exists certreferences(certreferenceid INTEGER, certreference TEXT, type TEXT, PRIMARY KEY(certreferenceid,certreference), FOREIGN KEY(certreferenceid) REFERENCES certs(certreferenceid) ON DELETE CASCADE);''')
            #hack:
            con.execute('''CREATE TABLE if not exists certrefcount(certreferenceid INTEGER);''')
            con.execute('''INSERT INTO certrefcount(certreferenceid) values(?);''', (0,))
            con.commit()
        except Exception as e:
            con.rollback()
            logger().error(e)
        con.close()
        self.lock.release()

    def connecttodb(func):
        import sqlite3
        def funcwrap(self, *args, **kwargs):
            temp = None
            self.lock.acquire()
            try:
                dbcon = sqlite3.connect(self.db_path)
                temp = func(self, dbcon, *args, **kwargs)
                dbcon.close()
            except Exception as e:
                st = str(e)
                if "tb_frame" in e.__dict__:
                    st = "{}\n\n{}".format(st, traceback.format_tb(e))
                logger().error("{}\n{}".format(st, type(func).__name__))
            self.lock.release()
            return temp
        return funcwrap

    @connecttodb
    def addentity(self, dbcon, _name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is not None:
            logger().info("name exist: {}".format(_name))
            return False
        if check_name(_name) == False:
            logger().info("name contains invalid elements")
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values (?,'default');''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delentity(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            #logger().info("name does not exist: {}".format(_name))
            return True
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def renameentity(self, dbcon, _name, _newname):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is not None:
            logger().info("newname already exist: {}".format(_newname))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE name=?;''', (_newname, _name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self, dbcon, _name, _certhash, nodetype="unknown", priority=20, _security="valid"):
        if _name is None:
            logger().error("name None")
        if nodetype is None:
            logger().error("nodetype None")
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash) == False:
            logger().error("hash contains invalid characters: {}".format(_certhash))
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname=cur.fetchone()
        if _oldname is not None:
            logger().info("hash already exist: {}".format(_certhash))
            return False

        #hack
        cur.execute('''SELECT certreferenceid FROM certrefcount''')
        count = cur.fetchone()[0]
        cur.execute('''UPDATE certrefcount SET certreferenceid=?''', (count+1,))
        #hack end
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,security,certreferenceid) values(?,?,?,?,?,?);''', (_name, _certhash, nodetype, priority, _security, count))

        dbcon.commit()
        return True

    @connecttodb
    def movehash(self,dbcon,_certhash,_newname):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_newname))
            return False

        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname = cur.fetchone()
        if _oldname is None:
            logger().info("certhash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE certhash=?;''', (_newname, _certhash,))

        dbcon.commit()
        return True

    @connecttodb
    def changetype(self, dbcon, _certhash, _type):
        if check_typename(_type,15) == False:
            logger().info("type contains invalid characters or is too long (maxlen: {}): {}".format(15, _type))
            return False
        if check_hash(_certhash) == False:
            logger().info("hash contains invalid characters")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET type=? WHERE certhash=? values(?,?,?);''', (_type, _certhash))

        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self, dbcon, _certhash, _priority):
        #convert str to int and fail if either no integer in string format
        # or datatype is something else except int
        if isinstance(_priority, str) == True and _priority.isdecimal() == False:
            logger().info("priority can not parsed as integer: {}".format(_priority))
            return False
        elif isinstance(_priority, str) == True:
            _priority=int(_priority)
        elif isinstance(_priority, int) == False:
            logger().info("priority has unsupported datatype: {}".format(type(_priority).__name__))
            return False

        if _priority < 0 or _priority > 100:
            logger().info("priority too big (>100) or smaller 0")
            return False
        
        if check_hash(_certhash) == False:
            logger().info("hash contains invalid characters: {}".format(_certhash))
            return False
        cur = dbcon.cursor()
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False

        cur.execute('''UPDATE certs SET priority=? WHERE certhash=? values(?,?,?);''', (_priority, _certhash))

        dbcon.commit()
        return True
    
    @connecttodb
    def changesecurity(self, dbcon, _certhash, _security):
        if check_hash(_certhash) == False:
            logger().info("hash contains invalid characters: {}".format(_certhash))
            return False
        if check_security(_certhash) == False:
            logger().info("hash contains invalid characters: {}".format(_certhash))
            return False
            
        cur = dbcon.cursor()
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False

        cur.execute('''UPDATE certs SET security=? WHERE certhash=?) values(?,?,?);''', (_security, _certhash))

        dbcon.commit()
        return True
    
    def updatehash(self, _certhash, certtype=None, priority=None, security=None):
        if certtype is not None:
            if self.changetype(_certhash, certtype) == False:
                return False
        if priority is not None:
            if self.changepriority(_certhash, priority) == False:
                return False
        if certtype is not None:
            if self.changesecurity(_certhash, security) == False:
                return False
        
    
    @connecttodb
    def delhash(self, dbcon, _certhash):
        if _certhash == "default":
            logger().error("tried to delete reserved hash 'default'")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))

        if cur.fetchone() is None:
            #logger().info("hash does not exist: {}".format(_certhash))
            return True

        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (_certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def get(self, dbcon, _certhash):
        if _certhash is None:
            return None
        if check_hash(_certhash) == False:
            logger().error("Invalid certhash: {}".format(_certhash))
            return None
        cur = dbcon.cursor()
        cur.execute('''SELECT name,type,priority,security,certreferenceid FROM certs WHERE certhash=?;''', (_certhash,))
        ret = cur.fetchone()
        if ret is not None and ret[0] == isself:
            logger().critical("\"{}\" is in the db".format(isself))
            return None
        return ret
    
    @connecttodb
    def listhashes(self, dbcon, _name, _nodetype = None):
        #if check_name(_name) == False:
        #    return None
        
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' ORDER BY priority DESC;''', (_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' AND type=? ORDER BY priority DESC;''', (_name, _nodetype))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    

    @connecttodb
    def listnodenames(self, dbcon, _nodetype = None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT DISTINCT name FROM certs ORDER BY name ASC;''')
        else:
            cur.execute('''SELECT DISTINCT name FROM certs WHERE type=? ORDER BY name ASC;''',(_nodetype,))
        out = cur.fetchall()
        if out is None:
            return None
        else:
            return [elem[0] for elem in out]
    
    @connecttodb
    def listnodenametypes(self, dbcon):
        cur = dbcon.cursor()
        cur.execute('''SELECT DISTINCT name,type FROM certs ORDER BY name ASC;''')
        out = cur.fetchall()
        if out is None:
            return None
        else:
            return out
    
    @connecttodb
    def listnodeall(self, dbcon, _nodetype = None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs ORDER BY priority DESC;''')
        else:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs ORDER BY priority WHERE type=? DESC;''', (_nodetype,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    
    #@connecttodb
    def certhash_as_name(self, _certhash):
        ret = self.get(_certhash)
        if ret is None:
            return None
        else:
            return ret[0]
    
    @connecttodb
    def exist(self, dbcon, _name, _hash = None):
        cur = dbcon.cursor()
        if _hash is None:
            cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        else:
            cur.execute('''SELECT name FROM certs WHERE name=? AND certhash=?;''', (_name, _hash))
        if cur.fetchone() is None:
            return False
        else:
            return True
    
    @connecttodb
    def addreference(self, dbcon, _referenceid, _reference, _reftype):
        if check_reference(_reference) == False:
            logger().error("reference invalid: {}".format(_reference))
            return False
        if check_reference_type(_reftype) == False:
            logger().error("reference type invalid: {}".format(_reftype))
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_referenceid, _reference))
        if cur.fetchone() is not None:
            logger().info("certreferenceid exist: {}".format(_referenceid))
            return False
        cur.execute('''INSERT INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (_referenceid, _reference, _reftype))
        dbcon.commit()
        return True
    
    @connecttodb
    def delreference(self, dbcon, _certreferenceid, _reference):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            #logger().info("certreferenceid/reference does not exist: {}, {}".format(_certreferenceid, _reference))
            return True
        cur.execute('''DELETE FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def updatereference(self, dbcon, _certreferenceid, _reference, _newreference, _newreftype):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            logger().info("certreferenceid/reference does not exist:{}, {}".format(_certreferenceid, _reference))
            return False
        if _reference != _newreference:
            cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _newreference))
            if cur.fetchone() is not None:
                logger().info("new reference does exist: {}, {}".format(_certreferenceid, _reference))
                return False
        if _reference != _newreference:
            cur.execute('''UPDATE certreferences SET certreference=?, type=? WHERE certreferenceid=? and certreference=?;''', (_newreference, _newreftype, _certreferenceid, _reference))
        else:
            cur.execute('''UPDATE certreferences SET type=? WHERE certreferenceid=? and certreference=?;''', (_newreftype, _certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def getreferences(self, dbcon, _referenceid, _reftype = None):
        if isinstance(_referenceid, int) == False:
            logger().error("invalid referenceid")
            return None
        cur = dbcon.cursor()
        if _reftype is None:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=?;''', (_referenceid,))
        else:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=? and type=?;''', (_referenceid, _reftype))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out

    #@connecttodb
    #def listreferences(self, dbcon, _reftype = None):
    #    cur = dbcon.cursor()
    #    cur.execute('''SELECT DISTINCT name,type FROM certreferences WHERE type ORDER BY name ASC;''',(_reftype, ))
    #    return cur.fetchall()
    
    #untested
    @connecttodb
    def findbyref(self, dbcon, _reference):
        if check_reference(_reference) == False:
            logger().error("invalid reference")
            return None
        cur = dbcon.cursor()
        cur.execute('''SELECT name,certhash,type,priority,security FROM certs WHERE certreferenceid IN (SELECT DISTINCT certreferenceid FROM certreferences WHERE certreference=?);''', (_reference,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
        
        #if out is None:
        #    return []
        #else:
        #    return out
