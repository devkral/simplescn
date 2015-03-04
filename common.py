#! /usr/bin/env python3

import logging
from OpenSSL import SSL,crypto
import ssl
import socket
import os
import platform
import sqlite3
import hashlib
from http import client

from subprocess import Popen,PIPE
key_size=4096
server_port=4040
#client_port=4041
sharedir=""

error="error"
success="success"
default_configdir="~/.simplescn/"


def generate_certs(_path):
    genproc=None
    _passphrase=input("(optional) Enter passphrase for encrypting key:\n")
    if _passphrase=="":
        genproc=Popen(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:"+str(key_size), "-keyout",_path+".priv", "-out",_path+".pub"],stdin=PIPE,stdout=PIPE, stderr=PIPE,universal_newlines=True)
        _answer=genproc.communicate("IA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")
    else:
        genproc=Popen(["openssl", "req", "-x509", "-aes256", "-newkey", "rsa:"+str(key_size),"-keyout",_path+".priv", "-out",_path+".pub"], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        _answer=genproc.communicate(_passphrase.strip("\n")+"\n"+_passphrase.strip("\n")+"\nIA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")

    #logging.debug(_answer[0])
    if _answer[1]!="":
        logging.debug(_answer[1])

def check_certs(_path):
    if os.path.exists(_path+".priv")==False or os.path.exists(_path+".pub")==False:
        return False
    _key=None
    with open(_path+".priv", 'r') as readin:
        #
        #,interact_wrap
        _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read(),input)
    if _key is None:
        return False

    if os.path.exists(_path+".pub")==True:
        is_ok=False
        with open(_path+".pub", 'r') as readin:
            try:
                _c=SSL.Context(SSL.TLSv1_2_METHOD)
                #_c.use_privatekey(_key)
                _c.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,readin.read()))
                #_c.check_privatekey()
                is_ok=True
            except Exception as e:
                logging.error(e)
        if is_ok==True:
            return True
    return False

def init_config_folder(_dir, prefix):
    if os.path.exists(_dir)==False:
        os.makedirs(_dir,0o700)
    else:
        os.chmod(_dir,0o700)
    _path="{}{}{}".format(_dir,os.sep,prefix)
    if os.path.exists(_path+"_name")==False:
        e=open(_path+"_name","w")
        if prefix=="client":
            e.write("{}/{}".format(platform.uname()[1],0))
        else:
            e.write("{}/{}".format(platform.uname()[1],server_port))
        e.close()
    if os.path.exists(_path+"_message")==False:
        e=open(_path+"_message","w")
        e.write("<message>")
        e.close()


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
    sslcont.options=sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_NO_COMPRESSION
    return sslcont

def gen_sslcont(path):
    sslcont=default_sslcont()
    if os.path.isdir(path)==True: #if dir, then capath, if file then cafile
        sslcont.load_verify_locations(capath=path)
    else:
        sslcont.load_verify_locations(path)
    return sslcont


def parse_response(response):
    if response.status==client.OK:
        return (True,response.read().decode("utf8"))
    return (False,response.read().decode("utf8"))


    
class VALNameError(Exception):
    msg="Name doesn't match"

class VALHashError(Exception):
    msg="Hash doesn't match"
    
class isself(object):
    def __str__(*args):
        return "is self"


class commonscn(object):
    capabilities=[]
    info=None
    priority=None
    name=None
    cert_hash=None
    scn_type="unknown"
    
    cache={"cap":"","info":"","priority":""}#,"hash":"","name":"","message":""
    
    def update_cache(self):
        self.cache["cap"]="{}/{}".format(success,self.scn_type)
        for elem in self.capabilities:
            self.cache["cap"]="{}/{}".format(self.cache["cap"],elem)
        
        self.cache["info"]="{}/{}/{}/{}/{}".format(success,self.scn_type,self.name,self.cert_hash,self.message)
        self.cache["priority"]="{}/{}".format(success,self.priority)
        

def dhash(ob):
    if type(ob).__name__=="str":
        return hashlib.sha256(bytes(ob,"utf8")).hexdigest()
    else:
        return hashlib.sha256(ob).hexdigest()
    
#gen hash for server, gen hash for transmitting
def dhash_salt(ob,salt):
    if type(ob).__name__=="str":
        ha=hashlib.sha256(bytes(ob,"utf8"))
    else:
        ha=hashlib.sha256(ob)
    ha.update(salt)
    return ha.hexdigest()


#hash on server, uses already hashed password (e.g. in file)
def gen_passwd_hash(passwd,salt):
    #hash hexdigest of hash of passwd
    ha=dhash(passwd)
    return dhash_salt(ha,salt)


def check_hash(_hashstr):
  if all(c in "0123456789abcdefABCDEF" for c in _hashstr):
    return True
  return False

def check_name(_name, maxlength=64):
  if all(c not in " \n\\$&?\0'%\"\n\r\t\b\x1A\x7F<>/" for c in _name) and \
     len(_name)<=maxlength: #name shouldn't be too big
    return True
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
            logging.error(e)
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
        self.db_path=dbpath
        try:
            con=sqlite3.connect(self.db_path)
        except Exception as e:
            logging.error(e)
            return
        try:
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
            con.commit()
        except Exception as e:
            con.rollback()
            logging.error(e)
        con.close()
        
    
    def connecttodb(func):
        def funcwrap(self,*args,**kwargs):
            temp=None
            try:
                dbcon=sqlite3.connect(self.db_path)
                temp=func(self,dbcon,*args,**kwargs)
                dbcon.close()
            except Exception as e:
                logging.error(e)
            return temp
        return funcwrap

    @connecttodb
    def addname(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is not None:
            logging.info("name exists")
            return False
        if check_name(_name)==False:
            logging.info("name contains invalid elements")
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values(?,"default");''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delname(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=?;',(_name,))
        if cur.fetchone() is None:
            logging.info("name doesn't exists")
            return False
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self,dbcon,_name,_certhash,nodetype=1,priority=20):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logging.info("name doesn't exists")
            return False
        
        if check_hash(_certhash)==False:
            logging.info("hash contains invalid characters")
            return False
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        if cur.fetchone() is not None:
            logging.info("hash already exists")
            return False
        
        cur.execute('''INSERT INTO certs(name,certhash,type,priority) values(?,?,?);''', (_name,_certhash,nodetype,priority))
        
        dbcon.commit()
        return True

    @connecttodb
    def changetype(self,dbcon,_name,_certhash,_type):
        if check_name(_type,10)==False:
            logging.info("type contains invalid characters, or is too long")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logging.info("name doesn't exists")
            return False
        if check_hash(_certhash)==False:
            logging.info("hash contains invalid characters")
            return False
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist")
            return False
        cur.execute('''UPDATE certs SET type=? WHERE name=? AND certhash=?) values(?,?,?);''', (_type,_name,_certhash))
        
        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self,dbcon,_name,_certhash,_priority):
        
        if type(_priority).__name__!="int" and _priority.isdecimal()==False:
            logging.info("priority no integer")
            return False
        elif type(_priority).__name__!="int":
            _priority=int(_priority)

        if _priority<0 or _priority>100:
            logging.info("priority too big (>100) or smaller 0")
            return False
        
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is None:
            logging.info("name doesn't exists")
            return False
        if check_hash(_certhash)==False:
            logging.info("hash contains invalid characters")
            return False
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist")
            return False

        
        cur.execute('''UPDATE certs SET priority=? WHERE name=? AND certhash=?) values(?,?,?);''', (_priority,_name,_certhash))
        
        dbcon.commit()
        return True
    
    @connecttodb
    def delhash(self,dbcon,_certhash,_name=None):
        cur = dbcon.cursor()
        if _name is None:
            cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))
        else:
            cur.execute('''SELECT certhash FROM certs WHERE name=? AND certhash=?;''',(_name,_certhash))
            
        if cur.fetchone() is None:
            if _name is None:
                logging.info("name/hash doesn't exists")
            else:
                logging.info("hash doesn't exists")
            return False
        
        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (_certhash,))
        dbcon.commit()
        return True
    
    @connecttodb
    def listcerts(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash,type,priority FROM certs WHERE name=?;''',(_name,))
        temmp=cur.fetchall()
        if temmp is None:
            return None
        temp=[]
        for elem in temmp:
            temp+=[elem[0],]
        return temp
    

    @connecttodb
    def listnames(self,dbcon):
        cur = dbcon.cursor()
        cur.execute('''SELECT name,certhash,priority FROM certs;''')
        temmp=cur.fetchall()
        if temmp is None:
            return None
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
            cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name))
        else:
            cur.execute('''SELECT name FROM certs WHERE name=? AND certhash=?;''',(_name,_hash))
        if cur.fetchone() is None:
            return False
        else:
            return True
        
