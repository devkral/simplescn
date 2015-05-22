#! /usr/bin/env python3

import os,sys,platform

sharedir=os.path.dirname(os.path.realpath(__file__))

#if platform.python_implementation()=="PyPy":
#    sys.path+=['', '/usr/lib/python34.zip', '/usr/lib/python3.4', '/usr/lib/python3.4/plat-linux', '/usr/lib/python3.4/lib-dynload', '/usr/lib/python3.4/site-packages', '/usr/lib/site-python']
import importlib
import logging
from OpenSSL import SSL, crypto
import ssl
import socket
#

import hashlib
import re
import threading
from http import client

#from subprocess import Popen,PIPE
key_size = 4096
server_port = 4040
#client_port=4041

error = "error"
success = "success"
default_configdir = "~/.simplescn/"



###### signaling  ######

class AddressFail(Exception):
    msg = "\"<address>:<port>\"\n\"[<address>]:<port>\""
class EnforcedPortFail(AddressFail):
    msg = "address is lacking\":<port>\"\n"+AddressFail.msg
class AddressEmptyFail(AddressFail):
    msg = "address is empty\n"+AddressFail.msg


class VALError(Exception):
    msg = "validation failed"
class VALNameError(VALError):
    msg = "Name does not match"

class VALHashError(VALError):
    msg = "Hash does not match"
    

class isself(object):
    def __str__(*args): #does this exist?
        return "isself"
    def __repr__(*args): #this exist but why doesn't it work
        return "isself"

#### logging ####

class scn_logger(logging.Logger):
    _defaultHandler=None
    lformat=None
    
    def __init__(self, _handler=logging.StreamHandler()):
        logging.Logger.__init__(self,"scn_logger")
        self.lformat=logging.Formatter('%(levelname)s::%(filename)s:%(lineno)d::%(funcName)s:: %(message)s')
        _handler.setFormatter(self.lformat)
        self.replaceHandler(_handler)
        
    def replaceHandler(self, newhandler):
        if self._defaultHandler is not None:
            self.removeHandler(self._defaultHandler)
        self.addHandler(newhandler)
        self._defaultHandler=newhandler
        
        
    def check(self,ret,level=logging.DEBUG):
        if ret[0]==True:
            return True
        else:
            if level!=0:
                #use of internal function
                self._log(level,ret[1],())
            return False


global loggerinst
loggerinst=None

def logger():
    return loggerinst
#class logger(scn_logger):
#    @classmethod
#    def __prepare__(metacls, name, bases, **kwds):
#        return loggerinst
#    
#    def __new__(cls, name, bases, namespace, **kwds):
#        result = type.__new__(cls, name, bases, dict(namespace))
#        result.members = tuple(namespace)
#        return result

def init_logger(_logger=scn_logger()):
    global loggerinst
    if loggerinst is None:
        loggerinst=_logger

##### init ######

#cert_name.emailAddress=""
#cert_name.localityName=""
def generate_certs(_path):
    _key = crypto.PKey()
    _key.generate_key(crypto.TYPE_RSA, key_size)
    _passphrase = "" #input("(optional) Enter passphrase for encrypting key:\n")
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
    with open(_path+".priv", 'wb') as writeout:
        writeout.write(privkey)
    with open(_path+".pub", 'wb') as writeout:
        writeout.write(pubkey)

def check_certs(_path):
    if os.path.exists(_path+".priv") == False or os.path.exists(_path+".pub") == False:
        return False
    _key = None
    with open(_path+".priv", 'r') as readin:
        #
        #,interact_wrap
        _key = crypto.load_privatekey(crypto.FILETYPE_PEM, readin.read(), input)
    if _key is None:
        return False

    if os.path.exists(_path+".pub") == True:
        is_ok = False
        with open(_path+".pub", 'r') as readin:
            try:
                _c = SSL.Context(SSL.TLSv1_2_METHOD)
                #_c.use_privatekey(_key)
                _c.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, readin.read()))
                #_c.check_privatekey()
                is_ok = True
            except Exception as e:
                logger().error(e)
        if is_ok==True:
            return True
    return False

def init_config_folder(_dir, prefix):
    if os.path.exists(_dir) == False:
        os.makedirs(_dir,0o700)
    else:
        os.chmod(_dir,0o700)
    _path=os.path.join(_dir,prefix)
    if os.path.exists(_path+"_name")==False:
        e=open(_path+"_name","w")
        if prefix=="client":
            e.write("{}/{}".format(os.uname()[1],0))
        else:
            e.write("{}/{}".format(os.uname()[1],server_port))
        e.close()
    if os.path.exists(_path+"_message")==False:
        e=open(os.path.join(_path, "_message"),"w")
        e.write("<message>")
        e.close()




##### etc ######


#work around crappy python ssl implementation
#which doesn't allow reads from strings
def workaround_ssl(text_cert):
    import tempfile
    t=tempfile.NamedTemporaryFile()
    t.write(text_cert)
    return t

def default_sslcont():
    sslcont=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslcont.set_ciphers("HIGH")
    sslcont.options=sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
    return sslcont

def gen_sslcont(path):
    sslcont=default_sslcont()
    if os.path.isdir(path)==True: #if dir, then capath, if file then cafile
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(path)
    return sslcont


def parse_response(response):
    try:
        if response.status==client.OK:
            return (True,response.read().decode("utf8"))
        return (False,response.read().decode("utf8"))
    except Exception as e:
        return (False, "reading response failed, reason: {}".format(e))


re_parse_url=re.compile("\\[?(.*)\\]?:([0-9]+)")
def scnparse_url(url,force_port=False):
    if type(url).__name__!='str':
        raise(AddressFail)
    if url=="":
        raise(AddressEmptyFail)
    _urlre=re.match(re_parse_url,url)
    if _urlre is not None:
        return _urlre.groups()
    elif force_port==False:
        return (url,server_port)
    raise(EnforcedPortFail)

class configmanager(object):
    db_path = None
    dbcon = None
    lock = None
    imported = False
    overlays={}
    defaults={}
    def __init__(self,_dbpath):
        self.db_path=_dbpath
        self.lock=threading.BoundedSemaphore(1)
        
        self.reload()
        #self.update(_defaults,_overlays)
        
    def __del__(self):
        if self.dbcon is not None:
            self.dbcon.close()
        
    
    def dbaccess(func):
        def funcwrap(self,*args,**kwargs):
            #if self.dbcon is None:
            #    raise(Exception("self.path"))
            self.lock.acquire()
            temp=None
            try:
                temp=func(self,self.dbcon,*args,**kwargs)
                
            except Exception as e:
                if "tb_frame" in e.__dict__:
                    st="{}\n\n{}".format(e,traceback.format_tb(e))
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
        self.dbcon=sqlite3.connect(self.db_path)
        cur = self.dbcon.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS main(name TEXT, val TEXT,PRIMARY KEY(name));''')
        cur.execute('''INSERT OR IGNORE INTO main(name,val) values ("state","false");''')
        self.dbcon.commit()
        self.lock.release()
        
    
    @dbaccess
    def update(self,dbcon,_defaults,_overlays={}):
        self.defaults=_defaults
        self.overlays=_overlays
        if dbcon is None:
            return True
        cur=dbcon.cursor()
        cur.execute('''SELECT name FROM main;''')
        _in_db=cur.fetchall()
        for elem in _defaults:
            cur.execute('''INSERT OR IGNORE INTO main(name,val) values (?,?);''',(elem,_defaults[elem]))
        if _in_db==None:
            return True
        for elem in _in_db:
            if elem[0] not in _defaults:
                cur.execute('''DELETE FROM main WHERE name=?;''',(elem[0],))
        dbcon.commit()
        return True
        
    @dbaccess
    def set(self,dbcon,name,value):
        if value is None:
            value="False"
        """if isinstance(value, bool)==True:
            if value==True:
                value="true"
            else:
                value="false" """
        if name in self.overlays or dbcon is None:
            self.overlays[name]=value
        if dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''UPDATE main SET val=? WHERE name=?;''',(str(value),name))
            dbcon.commit()
        return True
    
    def set_default(self,dbcon,name):
        return self.set(self.defaults[name])
        
    @dbaccess
    def get(self,dbcon,name):
        if name in self.overlays:
            if self.overlays[name] is None:
                return "False"
            else:
                return self.overlays[name]
        if dbcon is None:
            if name in self.overlays:
                if self.defaults[name] is None:
                    return "False"
                else:
                    return self.defaults[name]
            else:
                return None
        
        cur = dbcon.cursor()
        cur.execute('''SELECT val FROM main WHERE name=?;''',(name,))
        temp=cur.fetchone()
        if temp is None:
            return None
        if temp[0] in [None,"False"]:
            return "False"
        return temp[0]
    
    def getb(self,name):
        temp=self.get(name)
        if temp in [None,"","False"]:
            return False
        return True
    
        
    def __getitem__(self,_name):
        self.get(_name)
    
    #@self.configmanager.dbaccess
    def get_default(self,name):
        if name in self.defaults:
            return self.defaults[name]
        else:
            return None


class pluginmanager(object):
    pluginenv=None
    pathes_plugins=None
    path_plugins_config=None
    resources=None
    redirect_addr=""
    interfaces=["main"]
    plugins={}
    
    def __init__(self, _pathes_plugins, _path_plugins_config, pluginenv=sys.path, resources={}):
        self.pluginenv=pluginenv.copy()
        self.pathes_plugins=_pathes_plugins
        self.path_plugins_config=_path_plugins_config
        self.pluginenv=pluginenv
        self.resources=resources
        
    def list_plugins(self):
        temp={}
        for path in self.pathes_plugins:
            if os.path.isdir(path)==True:
                for plugin in os.listdir(path):
                    temp[plugin]=path
            
        return temp
    
    def clean_plugin_conf(self):
        lplugins=self.list_plugins()
        lconfig=os.listdir(self.path_plugins_config)
        for dbconf in lconfig:
            #remove .conf
            if dbconf[:-5] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config,"{}.conf".format(dbconf)))
    
    def init_plugins(self):
        for plugin in self.list_plugins().items():
            pconf=configmanager(os.path.join(self.path_plugins_config,plugin[0]))
            if pconf.getb("state")==False:
                continue
            pspec = importlib.machinery.PathFinder.find_spec(plugin[0],plugin[1])
            if pspec is not None:
                #init sys pathes
                newenv=self.pluginenv.copy()
                newenv.append(os.path.join(plugin[1], plugin[0]))
                pspec.submodule_search_locations = newenv
                #load module
                pload=pspec.loader.load_module()
                pconf.update(pload.defaults)
                pload.config = pconf
                pload.resources = self.resources # no copy because they can change
                pload.interfaces = self.interfaces.copy()
                #load interfaces
                ret = False
                
                try:
                    ret = pload.init()
                except Exception as e:
                    if "tb_frame" in e.__dict__:
                        st = "{}\n\n{}".format(e, traceback.format_tb(e))
                    else:
                        st = str(e)
                    logger().error(st)
                #receive is a function to overload, it get connections from handler
                if ret == True and "receive" in pload.__dict__:
                    self.plugins[plugin] = pload
    def register_remote(self,_addr):
        self.redirect_addr=_addr

    def delete_remote(self):
        self.redirect_addr=""


class commonscn(object):
    capabilities=[]
    info=None
    priority=None
    name=None
    cert_hash=None
    scn_type="unknown"
    pluginmanager=None
    #config=None
    
    #validactions=[]
    
    cache={"cap":"","info":"","prioty":""}#,"hash":"","name":"","message":""
    
    def update_cache(self):
        self.cache["cap"]="{}/{}".format(success,self.scn_type)
        for elem in self.capabilities:
            self.cache["cap"]="{}/{}".format(self.cache["cap"],elem)
        self.cache["info"]="{}/{}/{}/{}".format(success,self.scn_type,self.name,self.message) # be careful hash is included but can be faked if tls connection is MITM attacked
        #=priority+tpe
        self.cache["prioty"]="{}/{}/{}".format(success,self.priority,self.scn_type)

    def update_prioty(self):
        self.cache["prioty"]="{}/{}/{}".format(success,self.priority,self.scn_type)
    

def dhash(ob):
    if type(ob).__name__=="str":
        return hashlib.sha256(bytes(ob,"utf8")).hexdigest()
    else:
        return hashlib.sha256(ob).hexdigest()
    
#gen hash for server, gen hash for transmitting
def dhash_salt(ob,salt):
    if type(ob).__name__=="str":
        ha=hashlib.sha256(bytes(ob,"utf8"))
    elif None in [ob,salt]:
        raise(TypeError("ob:{}, salt:{}".format(ob,salt)))
    else:
        ha=hashlib.sha256(ob)
    ha.update(salt)
    return ha.hexdigest()


#hash on server, uses already hashed password (e.g. in file)
def gen_passwd_hash(passwd,salt):
    #hash hexdigest of hash of passwd
    ha=dhash(passwd)
    return dhash_salt(ha,salt)


"""def check_sqlitesafe(_name):
    if all(c not in " \n\\$&?\0'%\"\n\r\t\b\x1A\x7F<>/" for c in _name) and \
        "sqlite_" not in str(_name).lower():
        return True
    return False"""

def check_reference(_reference):
    if all(c not in "\0'\"\x1A\x7F" for c in _reference) and \
        len(_reference)<100:
        return True
    #logger().debug("invalid reference: {}".format(_reference))
    return False

def check_reference_type(_reference_type):
    if all(c in "0123456789abcdefghijklmnopqrstuvxyz_" for c in _reference_type) and \
        len(_reference_type)<15:
        return True
    #logger().debug("invalid referencetype: {}".format(_reference_type))
    return False

def check_hash(_hashstr):
    if all(c in "0123456789abcdefABCDEF" for c in _hashstr) and \
        len(_hashstr)==64:
        return True
    #logger().debug("invalid hash: {}".format(_hashstr))
    return False

def check_name(_name, maxlength=64):
    #ensure no bad characters
    #name shouldn't be too big
    #.:[]to differ name from ip address
    #name shouldn't be isself as it is used 
    if all(c not in " \\$&?\0'%\"\n\r\t\b\x1A\x7F<>/" for c in _name) and \
        all(c not in ".:[]" for c in _name) and \
        len(_name)<=maxlength and \
        _name!="isself":
        return True
    #logger().debug("invalid name (maxlength: {}): {}".format(maxlength, _name))
    return False

def check_typename(_name, maxlength=15):
    #ensure no bad characters
    #name shouldn't be too big
    #name shouldn't be isself as it is used
    if _name.isalpha()==True and \
        len(_name)<=maxlength and \
        _name!="isself":
        return True
    #logger().debug("invalid type: {}".format(_name))
    return False

def rw_socket(sockr,sockw,buffersize):
    while True:
        if bool(sockr.getsockopt(socket.SO_TCP_CLOSE))==False and \
           bool(sockr.getsockopt(socket.SO_TCP_CLOSING))==False:
            sockw.close()
            break
        if bool(sockw.getsockopt(socket.SO_TCP_CLOSE))==False and \
           bool(sockw.getsockopt(socket.SO_TCP_CLOSING))==False:
            sockr.close()
            break
        
        try:
            sockw.sendall(sockr.read(buffersize))
        except socket.timeout:
            sockw.close()
            break
        except Exception as e:
            logger().error(e)
            break
        
#def con_socket(sockown,sockdest,buffersize,_servicename):
#    redout=threading.Thread(target=rw_socket,args=(sockown,sockdest))
#    redout.daemon=True
#    redin=threading.Thread(target=rw_socket,args=(sockdest,sockown))
#    redin.daemon=True
#    redin.run()
#    redout.run()
#    redin.join()
    
                           
                           
class certhash_db(object):
    
    db_path=None
    
    def __init__(self,dbpath):
        import sqlite3
        self.db_path=dbpath
        try:
            con=sqlite3.connect(self.db_path)
        except Exception as e:
            logger().error(e)
            return
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
    
    def connecttodb(func):
        import sqlite3
        def funcwrap(self,*args,**kwargs):
            temp=None
            try:
                dbcon=sqlite3.connect(self.db_path)
                temp=func(self,dbcon,*args,**kwargs)
                dbcon.close()
            except Exception as e:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                logger().error("{}\n{}".format(st,func.__name__))
            return temp
        return funcwrap

    @connecttodb
    def addentity(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is not None:
            logger().info("name exist: {}".format(_name))
            return False
        if check_name(_name)==False:
            logger().info("name contains invalid elements")
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values (?,'default');''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delentity(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=?;',(_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def renameentity(self,dbcon,_name,_newname):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=?;',(_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        
        cur.execute('SELECT name FROM certs WHERE name=?;',(_newname,))
        if cur.fetchone() is not None:
            logger().info("newname already exist: {}".format(_newname))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE name=?;''', (_newname,_name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self,dbcon,_name,_certhash,nodetype="unknown",priority=20):
        
        if _name is None:
            logger().error("name None")
        if nodetype is None:
            logger().error("nodetype None")
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash)==False:
            logger().error("hash contains invalid characters: {}".format(_certhash))
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''',(_certhash,))
        _oldname=cur.fetchone()
        if _oldname is not None:
            logger().info("hash already exist: {}".format(_certhash))
            return False
            
        #hack
        cur.execute('''SELECT certreferenceid FROM certrefcount''')
        count=cur.fetchone()[0]
        cur.execute('''UPDATE certrefcount SET certreferenceid=?''',(count+1,))
        
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,certreferenceid) values(?,?,?,?,?);''', (_name,_certhash,nodetype,priority,count))
        
        dbcon.commit()
        return True
    
    @connecttodb
    def movehash(self,dbcon,_certhash,_newname):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_newname,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_newname))
            return False
            
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''',(_certhash,))
        _oldname=cur.fetchone()
        if _oldname is None:
            logger().info("certhash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE certhash=?;''', (_newname,_certhash,))
        
        dbcon.commit()
        return True
        
    @connecttodb
    def changetype(self,dbcon,_name,_certhash,_type):
        if check_typename(_type,15)==False:
            logger().info("type contains invalid characters or is too long (maxlen: {}): {}".format(15,_type))
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash)==False:
            logger().info("hash contains invalid characters")
            return False
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET type=? WHERE name=? AND certhash=?) values(?,?,?);''', (_type,_name,_certhash))
        
        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self,dbcon,_name,_certhash,_priority):

        #convert str to int and fail if either no integer in string format
        # or datatype is something else except int
        if type(_priority).__name__=="str" and _priority.isdecimal()==False:
            logger().info("priority can not parsed as integer: {}".format(_priority))
            return False
        elif type(_priority).__name__=="str":
            _priority=int(_priority)
        elif type(_priority).__name__!="int":
            logger().info("priority has unsupported datatype: {}".format(type(_priority).__name__))
            return False

        if _priority<0 or _priority>100:
            logger().info("priority too big (>100) or smaller 0")
            return False
        
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logger().info("name does not exist: {}".format(_name))
            return False
        if check_hash(_certhash)==False:
            logger().info("hash contains invalid characters: {}".format(_certhash))
            return False
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False

        
        cur.execute('''UPDATE certs SET priority=? WHERE name=? AND certhash=?) values(?,?,?);''', (_priority,_name,_certhash))
        
        dbcon.commit()
        return True
    
    @connecttodb
    def delhash(self,dbcon,_certhash,_name=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
            
        if cur.fetchone() is None:
            logger().info("hash does not exist: {}".format(_certhash))
            return False
        
        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (_certhash,))
        dbcon.commit()
        return True
    
    @connecttodb
    def get(self,dbcon,_name,_certhash):
        cur = dbcon.cursor()
        cur.execute('''SELECT type,priority,certreferenceid FROM certs WHERE name=? AND certhash=?;''',(_name,_certhash))
        return cur.fetchone()
    
    @connecttodb
    def listhashes(self,dbcon,_name,_nodetype=None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,certreferenceid FROM certs WHERE name=? ORDER BY priority DESC;''',(_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,certreferenceid FROM certs WHERE name=? and type=? ORDER BY priority DESC;''',(_name,_nodetype))
        return cur.fetchall()
    

    @connecttodb
    def listnodenames(self, dbcon, _nodetype=None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT DISTINCT name FROM certs ORDER BY name ASC;''')
        else:
            cur.execute('''SELECT DISTINCT name FROM certs WHERE type=? ORDER BY name ASC;''',(_nodetype,))
        temmp=cur.fetchall()
        if temmp is None:
            return None
        return [elem[0] for elem in temmp]
    
    @connecttodb
    def listnodenametypes(self,dbcon):
        cur = dbcon.cursor()
        cur.execute('''SELECT DISTINCT name,type FROM certs ORDER BY name ASC;''')
        return cur.fetchall()
    
    @connecttodb
    def listnodeall(self,dbcon, _nodetype=None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT name,certhash,type,priority,certreferenceid FROM certs ORDER BY priority DESC;''')
        else:
            cur.execute('''SELECT name,certhash,type,priority,certreferenceid FROM certs ORDER BY priority WHERE type=? DESC;''',(_nodetype,))
        temmp=cur.fetchall()
        #if temmp is None:
        #    return None
        return temmp
    
    @connecttodb
    def certhash_as_name(self,dbcon,_certhash):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''',(_certhash,))
        temp=cur.fetchone()
        if temp is None:
            return None
        else:
            return temp[0]
    
    @connecttodb
    def exist(self,dbcon,_name,_hash=None):
        cur = dbcon.cursor()
        if _hash is None:
            cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        else:
            cur.execute('''SELECT name FROM certs WHERE name=? AND certhash=?;''',(_name, _hash))
        if cur.fetchone() is None:
            return False
        else:
            return True
    
    @connecttodb
    def addreference(self,dbcon,_referenceid,_reference,_reftype):
        if check_reference(_reference)==False:
            logger().error("reference invalid: {}".format(_reference))
            return False
        if check_reference_type(_reftype)==False:
            logger().error("reference type invalid: {}".format(_reftype))
            return False
        cur = dbcon.cursor()
        cur.execute('''INSERT OR REPLACE INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (_referenceid, _reference, _reftype))
        dbcon.commit()
        return True
    
    @connecttodb
    def delreference(self,dbcon,_certreferenceid,_reference):
        cur = dbcon.cursor()
        cur.execute('SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;',(_certreferenceid,_reference))
        if cur.fetchone() is None:
            logger().info("certreferenceid/reference does not exist: {}".format(_certreferenceid,_reference))
            return False
        cur.execute('''DELETE FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid,_reference))
        dbcon.commit()
        return True

    @connecttodb
    def getreferences(self,dbcon,_referenceid, _reftype=None):
        cur = dbcon.cursor()
        if _reftype is None:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=?;''',(_referenceid,))
        else:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=? and type=?;''',(_referenceid, _reftype))
        return cur.fetchall()
    
    @connecttodb
    def findbyref(self,dbcon,_reference):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE reference=?;''',(_reference))
        temp=cur.fetchone()
        if temp is None:
            return None
        cur.execute('''SELECT name,certhash,type,priority FROM certs WHERE certreferenceid=?;''',(_referenceid))
        return cur.fetchall()
