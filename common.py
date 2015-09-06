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
from OpenSSL import SSL, crypto
import ssl
import socket
import traceback

import hashlib
import re
import threading
import json
import base64
import time
#from http import client
from urllib import parse

# small nonces mean more collisions
nonce_size = 20
salt_size = 10
key_size = 4096
server_port = 4040
default_buffer_size = 1400
#maxread = 1500
max_serverrequest_size = 4000
confdb_ending=".confdb"
#client_port=4041


isself = 'isself'
default_configdir = '~/.simplescn/'

DEFAULT_HASHALGORITHM = "sha512"
DEFAULT_HASHALGORITHM_len=128

###### signaling ######


class AddressFail(Exception):
    msg = '"<address>[:<port>]": '
class EnforcedPortFail(AddressFail):
    msg = 'address is lacking ":<port>"'
class AddressEmptyFail(AddressFail):
    msg = '{} address is empty'.format(AddressFail.msg)


class VALError(Exception):
    msg = 'validation failed'
class VALNameError(VALError):
    msg = 'Name spoofed/does not match'
class VALHashError(VALError):
    msg = 'Hash does not match'
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
loggerinst=None

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
        return getpass(msg)
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

#cert_name.emailAddress=""
#cert_name.localityName=""
def generate_certs(_path):
    _key = crypto.PKey()
    _key.generate_key(crypto.TYPE_RSA, key_size)
    _passphrase = pwcallmethod("(optional) Enter passphrase for encrypting key:\n")()
    if _passphrase != "":
        _passphrase2 = pwcallmethod("Retype:\n")()
        if _passphrase != _passphrase2:
            return False
    cert = crypto.X509()
    cert_name = cert.get_issuer()
    cert_name.countryName = "IA"
    cert_name.stateOrProvinceName = "simple-scn"
    cert_name.organizationName = "secure communication nodes"
    cert_name.commonName = "secure communication nodes"
    cert.set_issuer(cert_name)
    cert.set_serial_number(0)
    cert.set_version(0)
    cert.set_pubkey(_key)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(0)
    #cert.add_extensions([
    #crypto.X509Extension("basicConstraints", True,
    #                    "CA:TRUE, pathlen:0"),
    #crypto.X509Extension("keyUsage", True,
    #                    "keyCertSign, cRLSign"),
    #crypto.X509Extension("subjectKeyIdentifier", False, "hash",
    #                    subject=cert_name)])
    cert.sign(_key, "sha512")
    if _passphrase == "":
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, _key)
    else:
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, _key, "CAMELLIA256", _passphrase)
    pubkey = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    with open("{}.priv".format(_path), 'wb') as writeout:
        writeout.write(privkey)
    with open("{}.pub".format(_path), 'wb') as writeout:
        writeout.write(pubkey)
    return True

def check_certs(_path):
    if os.path.exists("{}.priv".format(_path)) == False or os.path.exists("{}.pub".format(_path)) == False:
        return False
    _key = None
    with open("{}.priv".format(_path), 'r') as readin:
        #
        #,interact_wrap
        _key = crypto.load_privatekey(crypto.FILETYPE_PEM, readin.read(), input)
    if _key is None:
        return False

    if os.path.exists("{}.pub".format(_path)) == True:
        is_ok = False
        with open("{}.pub".format(_path), 'r') as readin:
            try:
                _c = SSL.Context(SSL.TLSv1_2_METHOD)
                #_c.use_privatekey(_key)
                _c.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, readin.read()))
                #_c.check_privatekey()
                is_ok = True
            except Exception as e:
                logger().error(e)
        if is_ok == True:
            return True
    return False

def init_config_folder(_dir, prefix):
    if os.path.exists(_dir) == False:
        os.makedirs(_dir, 0o700)
    else:
        os.chmod(_dir, 0o700)
    _path = os.path.join(_dir, prefix)
    if os.path.exists("{}_name".format(_path)) == False:
        e = open("{}_name".format(_path), "w")
        if prefix == "client":
            e.write("{}/{}".format(os.uname()[1], 0))
        else:
            e.write("{}/{}".format(os.uname()[1], server_port))
        e.close()
    if os.path.exists(_path+"_message") == False:
        e=open("{}_message".format(_path), "w")
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
    if type(url).__name__ != 'str':
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
    defaults = {"state": "False"}
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
            temp=None
            try:
                temp=func(self, self.dbcon, *args, **kwargs)
            except Exception as e:
                if hasattr(e,"tb_frame"):
                    st="{}\n\n{}".format(e, traceback.format_tb(e))
                else:
                    st="{}".format(e)
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
        _defaults["state"] = "False"
        self.defaults = _defaults
        self.overlays = _overlays
        if dbcon is None:
            return True
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM main;''')
        _in_db = cur.fetchall()
        for elem in _defaults:
            cur.execute('''INSERT OR IGNORE INTO main(name,val) values (?,?);''', (elem, _defaults[elem]))
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
            logger.error("name not string")
            return False
        if name not in self.defaults:
            logger.error("not in defaults")
            return False
            
        
        if value is None:
            value="False"
        """if isinstance(value, bool)==True:
            if value==True:
                value="true"
            else:
                value="false" """
        
        if name in self.overlays or dbcon is None:
            self.overlays[name] = str(value)
        if dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''UPDATE main SET val=? WHERE name=?;''', (str(value), name))
            dbcon.commit()
        return True
    
    def set_default(self, name):
        if name not in self.defaults:
            return False
        return self.set(name, self.defaults[name])
        
    @dbaccess
    def get(self, dbcon, name):
        if isinstance(name, str) == False:
            logger.error("name not string")
            return None
        if name in self.overlays:
            if self.overlays[name] is None:
                return "False"
            else:
                return str(self.overlays[name])
        if dbcon is None:
            if self.defaults[name] is None:
                return "False"
            else:
                return self.defaults[name]
        
        cur = dbcon.cursor()
        cur.execute('''SELECT val FROM main WHERE name=?;''', (name,))
        temp = cur.fetchone()
        if temp is None:
            return None
        if temp[0] in [None,"False", "false"]:
            return "False"
        if temp[0] in ["True", "true"]:
            return "True"
        return temp[0]
    
    def getb(self, name):
        temp = self.get(name)
        if temp in [None, "", "False", "false"]:
            return False
        return True
    
    #@self.configmanager.dbaccess
    def get_default(self,name):
        if name in self.defaults:
            return self.defaults[name]
        else:
            return None


class pluginmanager(object):
    pluginenv = None
    pathes_plugins = None
    path_plugins_config = None
    resources = None
    redirect_addr = ""
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
                    if "tb_frame" in e.__dict__:
                        st = "{}\n\n{}".format(e, traceback.format_tb(e))
                    else:
                        st = str(e)
                    logger().error("Plugin \"{}\":\n{}".format(plugin[0], st))
                    continue
            if "defaults" not in pload.__dict__ or \
                "init" not in pload.__dict__:
                continue
            try:
                # not changeable default
                pload.defaults["state"] = False
            except Exception as e:
                logger().error("Plugin \"{}\":\ndefaults is a dict?:\n{}".format(plugin[0],e))
                continue
            pconf.update(pload.defaults)
            pload.config = pconf # no copy because it is the only user
            pload.resources = self.resources # no copy because they can change
            pload.interfaces = self.interfaces.copy() # copy because of isolation
            pload.path = pluginpath # no copy because it is the only user
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
"salt": None,
"timestamp": None,
"realm": None
}


auth_struct = {
"auth": None,
"timestamp": None
#"nonce": None,
#"saveserver": None
}



class scnauth_server(object):
    request_expire_time = 300 # in secs
    # internal salt for memory protection
    salt = None
    # auth realms
    realms = None
    hashalgorithm = None
    
    def __init__(self, _hashalgo=DEFAULT_HASHALGORITHM):
        self.realms = {}
        self.hashalgorithm=_hashalgo
        self.salt = str(base64.urlsafe_b64encode(os.urandom(salt_size)), "utf8")

    def request_auth(self,  realm):
        rauth = authrequest_struct.copy()
        rauth["algo"] = self.hashalgorithm
        rauth["salt"] = self.salt
        rauth["timestamp"] = int(time.time())
        rauth["realm"] = realm
        return rauth
    
    # deactivate clientpubcert_hash for now as ssl doesn't send clientcert
    def verify(self, realm, authdict, clientpubcert_hash=""):
        if realm not in self.realms or self.realms[realm] is None:
            return True
        if realm not in authdict:
            return False
        if authdict["timestamp"].isdecimal() == False:
            logger().warning("Timestamp not a number")
            return False
        if int(authdict["timestamp"])< int(time.time())-self.request_expire_time:
            return False
        a=self.realms[realm]
        if dhash((a[0], clientpubcert_hash,authdict[realm]["timestamp"]), a[1]) == authdict[realm]["auth"]: #, authdict["nonce"]
            return True
        return False
    def init_realm(self,realm, pwhash):
        self.realms[realm] = dhash((pwhash, realm, self.salt), self.hashalgorithm)


class scnauth_client(object):
    # save credentials
    save_auth = None
    
    def __init__(self):
        self.save_auth = {}
    
    # deactivate pubcert_hash for now as ssl doesn't send clientcert
    def auth(self, pw, authreq_ob, pubcert_hash="", savedata=None):
        #nonce = str(base64.urlsafe_b64encode(os.urandom(nonce_size)))
        realm = authreq_ob["realm"]
        #dauth["nonce"] = nonce
        pre = dhash((dhash(pw, authreq_ob["algo"]), authreq_ob["realm"]), authreq_ob["algo"])
        if savedata != None:
            saveid = savedata 
            if saveid not in self.save_auth:
                self.save_auth[saveid]={}
            self.save_auth[saveid][realm] = (pre, authreq_ob["algo"])
        return self.asauth(pre,  authreq_ob, pubcert_hash=pubcert_hash)
    
    def asauth(self, pre, authreq_ob, pubcert_hash=""):
        if pre is None:
            return None
        dauth = auth_struct.copy()
        dauth["timestamp"] = authreq_ob["timestamp"]
        authreq_ob["realm"]
        dauth["auth"] = dhash((pre, pubcert_hash, authreq_ob["timestamp"]), authreq_ob["algo"])
        return dauth

    def saveauth(self, realm, pw, savedata):
        saveid = savedata
        pre = dhash((dhash(pw, DEFAULT_HASHALGORITHM), realm), DEFAULT_HASHALGORITHM)
        if saveid not in self.save_auth:
            self.save_auth[saveid]={}
        self.save_auth[saveid][realm] = (pre, DEFAULT_HASHALGORITHM)
        
    
    # deactivate pubcert_hash for now as ssl doesn't send clientcert
    def reauth(self, savedata, authreq_ob, pubcert_hash=""):
        saveid = savedata
        if saveid not in self.save_auth:
            return authreq_ob.get("realm"), None
        if authreq_ob.get("realm") not in self.save_auth[saveid]:
            return authreq_ob.get("realm"), None
        return self.auth(self.save_auth[saveid][authreq_ob["realm"]], authreq_ob, pubcert_hash=pubcert_hash)


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
    
    cache={"cap":"", "info":"", "prioty":""}
    
    def __del__(self):
        self.isactive = False
    
    def update_cache(self):
        self.cache["cap"] = json.dumps(gen_result({"caps": self.capabilities}, True))
        self.cache["info"] = json.dumps(gen_result({"type": self.scn_type, "name": self.name, "message":self.message}, True))
        self.cache["prioty"] = json.dumps(gen_result({"priority": self.priority, "type": self.scn_type}, True))

    def update_prioty(self):
        self.cache["prioty"] = json.dumps(gen_result({"priority": self.priority, "type": self.scn_type}, True))


def dhash(oblist, algo=DEFAULT_HASHALGORITHM):
    if algo not in hashlib.algorithms_available:
        logger().error("Hashalgorithm not available: {}".format(algo))
        return None
    if isinstance(oblist, (list, tuple))==False:
        oblist = [oblist,]
    hasher=hashlib.new(algo)
    ret=""
    for ob in oblist:
        tmp = hasher.copy()
        tmp.update(bytes(ret,"utf8"))
        if isinstance(ob, bytes):
            tmp.update(ob)
        elif isinstance(ob, str):
            tmp.update(bytes(ob, "utf8"))
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
        _type = value[0] # remove documentation string
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
            error=[]
            if check_args(obdict, requires, optional, error=error) == False:
                return False, "check_args failed ({}) arg: {}, reason:{}".format(func.__name__, *error), isself, self.cert_hash
            resp = func(self, obdict)
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
        elif isinstance(inp, str) == False:
            if len(splitted)==2:
                #splitted in format charset=utf-8
                split2 = splitted[1].split("=")
                charset = split2[1].strip().rstrip()
            string = str(inp,charset)
        else:
            string = inp
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
"""def check_sqlitesafe(_name):
    if all(c not in " \n\\$&?\0'%\"\n\r\t\b\x1A\x7F<>/" for c in _name) and \
        "sqlite_" not in str(_name).lower():
        return True
    return False"""

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


def check_hash(_hashstr):
    if _hashstr is None:
        return False
    if len(_hashstr) != DEFAULT_HASHALGORITHM_len:
        return False
    if all(c in "0123456789abcdefABCDEF" for c in _hashstr) == False:
        return False
    return True

def check_name(_name, maxlength = 64):
    if _name is None:
        return False
    # name shouldn't be too long
    if len(_name) > maxlength:
        return False
    # ensure no bad characters
    if any(c in " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/" for c in _name):
        return False
    # no .:[]to differ name from ip address
    #name shouldn't be isself as it is used 
    if any(c in ".:[]" for c in _name) or _name == isself:
        return False
    return True

def check_typename(_type, maxlength = 15):
    if _type is None:
        return False
    # type shouldn't be too long
    if len(_type) > maxlength:
        return False
    # ensure no bad characters
    if _type.isalpha() == False:
        return False
    # type shouldn't be isself as it is used
    if _type == isself:
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
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, certreferenceid INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
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
    def addhash(self, dbcon, _name, _certhash, nodetype="unknown", priority=20):
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
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,certreferenceid) values(?,?,?,?,?);''', (_name, _certhash, nodetype, priority, count))

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
    def changetype(self, dbcon, _name, _certhash, _type):
        if check_typename(_type,15) == False:
            logger().info("type contains invalid characters or is too long (maxlen: {}): {}".format(15, _type))
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash) == False:
            logger().info("hash contains invalid characters")
            return False
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET type=? WHERE name=? AND certhash=?) values(?,?,?);''', (_type, _name, _certhash))

        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self, dbcon, _name, _certhash, _priority):
        #convert str to int and fail if either no integer in string format
        # or datatype is something else except int
        if type(_priority).__name__ == "str" and _priority.isdecimal() == False:
            logger().info("priority can not parsed as integer: {}".format(_priority))
            return False
        elif type(_priority).__name__ == "str":
            _priority=int(_priority)
        elif type(_priority).__name__ != "int":
            logger().info("priority has unsupported datatype: {}".format(type(_priority).__name__))
            return False

        if _priority < 0 or _priority > 100:
            logger().info("priority too big (>100) or smaller 0")
            return False

        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash) == False:
            logger().info("hash contains invalid characters: {}".format(_certhash))
            return False
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False

        cur.execute('''UPDATE certs SET priority=? WHERE name=? AND certhash=?) values(?,?,?);''', (_priority, _name, _certhash))

        dbcon.commit()
        return True
    
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
    def get(self, dbcon, _name, _certhash):
        cur = dbcon.cursor()
        cur.execute('''SELECT type,priority,certreferenceid FROM certs WHERE name=? AND certhash=?;''', (_name, _certhash))
        return cur.fetchone()
    
    @connecttodb
    def listhashes(self, dbcon, _name, _nodetype = None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,certreferenceid FROM certs WHERE name=? AND certhash!='default' ORDER BY priority DESC;''', (_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,certreferenceid FROM certs WHERE name=? AND certhash!='default' AND type=? ORDER BY priority DESC;''', (_name, _nodetype))
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
            cur.execute('''SELECT name,certhash,type,priority,certreferenceid FROM certs ORDER BY priority DESC;''')
        else:
            cur.execute('''SELECT name,certhash,type,priority,certreferenceid FROM certs ORDER BY priority WHERE type=? DESC;''', (_nodetype,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    
    @connecttodb
    def certhash_as_name(self, dbcon, _certhash):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        temp = cur.fetchone()
        if temp is None:
            return None
        elif temp[0] == isself:
            logger().error("reserved name in db: "+isself)
            return None
        else:
            return temp[0]
    
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
        cur = dbcon.cursor()
        cur.execute('''SELECT name,certhash,type,priority FROM certs WHERE certreferenceid IN (SELECT DISTINCT certreferenceid FROM certreferences WHERE reference=?);''', (_reference,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
