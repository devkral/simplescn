#! /usr/bin/env python3

import logging
from OpenSSL import SSL,crypto
import ssl
#import socket
import os
import platform
import sqlite3
import hashlib
from http import client

from subprocess import Popen,PIPE
key_size=4096
server_port=4040
client_port=4041

error="error/"
success="success/"
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

def init_config_folder(_dir):
    if os.path.exists(_dir)==False:
        os.makedirs(_dir,0o700)
    else:
        os.chmod(_dir,0o700)
    if os.path.exists(_dir+os.sep+"client")==False:
        e=open(_dir+os.sep+"client","w")
        e.write("{}/{}".format(platform.uname()[1],client_port))
        e.close()
    if os.path.exists(_dir+os.sep+"server")==False:
        e=open(_dir+os.sep+"server","w")
        e.write("{}/{}".format(platform.uname()[1],server_port))
        e.close()
    if os.path.exists(_dir+os.sep+"/message")==False:
        e=open(_dir+os.sep+"message","w")
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


def dhash(ob):
    if type(ob).__name__=="str":
        return hashlib.sha256(bytes(ob,"utf8")).hexdigest()
    else:
        return hashlib.sha256(ob).hexdigest()
    
class VALNameError(Exception):
    msg="Name doesn't match"

class isself(object):
    def __str__(*args):
        return "is calling object"
    
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
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, PRIMARY KEY(name), UNIQUE(certhash));''')
            con.commit()
        except Exception as e:
            con.rollback()
            logging.error(e)
        con.close()
        
    
    def connecttodb(func):
        def funcwrap(self,*args,**argvs):
            temp=None
            try:
                dbcon=sqlite3.connect(self.db_path)
                temp=func(self,dbcon,*args,**argvs)
                dbcon.close()
            except Exception as e:
                logging.error(e)
            return temp
        return funcwrap

    @connecttodb
    def addname(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=?;',(_name,))
        if cur.fetchone() is not None:
            return False
        cur.execute('INSERT INTO certs(name) values(?);', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delname(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=?;',(_name,))
        if cur.fetchone() is None:
            return False
        cur.execute('DELETE FROM certs WHERE name=?;', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self,dbcon,_name,_certhash):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=? AND certhash=?;',(_name,_certhash))
        if cur.fetchone() is not None:
            return False
        cur.execute('INSERT INTO certs(name,certhash) values(?,?);', (_name,_certhash))
        
        dbcon.commit()
        return True

    @connecttodb
    def delhash(self,dbcon,_name,_certhash):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE name=? AND certhash=?;',(_name,_certhash))
        if cur.fetchone() is None:
            return False
        cur.execute('DELETE FROM certs WHERE name=? AND certhash=?;', (_name,_certhash))
        dbcon.commit()
        return True
    
    @connecttodb
    def listname(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('SELECT certhash FROM certs WHERE name=?;',(_name,))
        temp=[]
        for elem in cur.fetchall():
            temp+=[elem[0],]
        return temp
    
    @connecttodb
    def certhash_as_name(self,dbcon,_certhash):
        cur = dbcon.cursor()
        cur.execute('SELECT name FROM certs WHERE certhash=?;',(_certhash,))
        return cur.fetchone()
