#! /usr/bin/env python3

import logging
from OpenSSL import SSL,crypto
import ssl
#import socket
import os
import platform

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
    return response.read().decode("utf8")
"""
  # ok for the first step
def scn_connect_nocert(_server_addr,tries=1):
    if bool(_server_addr)==False:
        return None
    if len(_server_addr)<2:
        _server_addr=(_server_addr[0],server_port)
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_options(SSL.OP_SINGLE_DH_USE)
    temp_context.set_session_cache_mode(SSL.SESS_CACHE_OFF)
    temp_context.set_cipher_list("HIGH")

    for count in range(0,tries):
        tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #don't use settimeout, pyopenssl error
        tempsocket = SSL.Connection(temp_context,tempsocket)
        try:
            #connect with ssl handshake
            tempsocket.connect(_server_addr)
            tempsocket.do_handshake()
        except Exception as e:
            raise(e)
        # TODO: works because loop broken
        tempsocket.setblocking(True)
        return tempsocket
    return None

    
#secure connection
def connect_cert(_server_addr, _cert=None, tries=1):
    if len(_server_addr)<2:
        _server_addr=(_server_addr[0],server_port)
    
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_options(SSL.OP_SINGLE_DH_USE)
    temp_context.set_session_cache_mode(SSL.SESS_CACHE_OFF)
    temp_context.set_cipher_list("HIGH")
  
    if _cert!=None:
        temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,_cert))
    else:
        temp_context.set_default_verify_paths()
    for count in range(0,tries):
        tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #don't use settimeout, pyopenssl error
        tempsocket = SSL.Connection(temp_context,tempsocket)
        try:
            #connect with ssl handshake
            tempsocket.connect(_server_addr)
            tempsocket.do_handshake()
        except Exception as e:
            raise(e)
        # TODO: works because loop broken
        tempsocket.setblocking(True)
        return tempsocket
    return None
"""
