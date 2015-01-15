#! /usr/bin/env python3

#import SSL as ssln
from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import logging
import socket
import hashlib
import sys,signal,threading
from os import path

from common import success,error,server_port,client_port,check_certs,generate_certs,init_config_folder,default_configdir

class client_client(object):
    name=None
    cert_hash=None
    port=None

    
    def __init__(self,_name,pub_cert_hash,_port):
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.port=_port

    def register(self,server_addr,_sslcontext=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        """if _sslcontext==None:
            con=client.HTTPSConnection(server_addr[0],server_addr[1])
        else:
            con=client.HTTPSConnection(server_addr[0],server_addr[1],context=_sslcontext)"""
        con=client.HTTPConnection(server_addr[0],server_addr[1])
        
        con.request("GET", "/register/{}/{}/{}".format(self.name,self.cert_hash,self.port))
        
        return con.getresponse() #[0]==200
    
    def connect(self,server_addr,_name,_hash,_sslcontext=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        """if _sslcontext==None:
            con=client.HTTPSConnection(server_addr[0],server_addr[1])
        else:
            con=client.HTTPSConnection(server_addr[0],server_addr[1],context=_sslcontext)"""
        con=client.HTTPConnection(server_addr[0],server_addr[1])
        con.request("GET", "/connect/{}/{}".format(_name,_hash))
        return con.getresponse()

    def get(self,server_addr,_name,_hash,_sslcontext=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        """if _sslcontext==None:
            con=client.HTTPSConnection(server_addr[0],server_addr[1])
        else:
            con=client.HTTPSConnection(server_addr[0],server_addr[1],context=_sslcontext)"""
        con=client.HTTPConnection(server_addr[0],server_addr[1])
        con.request("GET", "/get/{}/{}".format(_name,_hash))
        return con.getresponse()
    def cert(self,server_addr,_sslcontext=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        """if _sslcontext==None:
            con=client.HTTPSConnection(server_addr[0],server_addr[1])
        else:
            con=client.HTTPSConnection(server_addr[0],server_addr[1],context=_sslcontext)"""
        con=client.HTTPConnection(server_addr[0],server_addr[1])
        con.request("GET", "/cert")
        return con.getresponse()
    
    
    def listnames(self,server_addr,_sslcontext=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        """if _sslcontext==None:
            con=client.HTTPSConnection(server_addr[0],server_addr[1])
        else:
            con=client.HTTPSConnection(server_addr[0],server_addr[1],context=_sslcontext)"""
        con=client.HTTPConnection(server_addr[0],server_addr[1])
        con.request("GET", "/listnames")
        return con.getresponse()

    def getservice(self,client_addr,_service):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPConnection(client_addr[0],client_addr[1])
        con.request("GET", "/get/{}".format(_service))
        return con.getresponse()

    def registerservice(self,client_addr,_service,_port):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPConnection(client_addr[0],client_addr[1])
        con.request("GET", "/register/{}/{}".format(_service,_port))
        return con.getresponse()

    def listservices(self,client_addr):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPConnection(client_addr[0],client_addr[1])
        con.request("GET", "/listservices")
        return con.getresponse()
    
    def info(self,client_addr):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPConnection(client_addr[0],client_addr[1])
        con.request("GET", "/info")
        return con.getresponse()
    
class client_server(object):
    name=""
    msg=""
    pub_cert=""
    spmap={}
    def __init__(self,_name,_msg,_pub_cert):
        self.name=_name
        self.msg=_msg
        self.pub_cert=_pub_cert.decode("utf8")
    def cert(self,_addr):
        return success+self.pub_cert
    def info(self,_addr):
        return success+self.msg
    def get(self,_service,_addr):
        if _service not in self.spmap:
            return "{}service".format(error)
        return "{}{}".format(success,self.spmap[_service])
    def listservices(self,_addr):
        temp=""
        for _service in self.spmap:
            temp="{}\n{}".format(_service,temp)
        return success+temp
    def register(self,_service,_port,_addr):
        if _addr[0] in ["localhost","127.0.0.1","::1"]:
            self.spmap[_service]=_port
            return success
        return error
class client_handler(BaseHTTPRequestHandler):
    linkback=None
    validactions=["cert","info","get","register","listservices"]

    
    def index(self):
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        self.wfile.write("TODO")

    def do_GET(self):
        _path=self.path[1:].split("/")
        if _path[0]=="":
            self.index()
            return
        action=_path[0]
        _path=_path+[self.client_address,]
        if action not in self.validactions:
            self.send_error(400,"invalid actions")
            return
        try:
            func=type(self.linkback).__dict__[action]
            response=func(self.linkback,*_path[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                self.send_error(500,str(e))
            return
        respparse=response.split("/",1)
        if respparse[0]=="error":
            self.send_error(400,respparse[1])
        else:
            self.send_response(200)
            self.send_header('Content-type',"text")
            self.end_headers()
            self.wfile.write(bytes(respparse[1],"utf8"))
        
class http_client_server(HTTPServer,client_server):
    client_server=None
    
    
    def __init__(self, _client_address,certs,name,message):
        e=client_handler
        self.client_server=client_server(name,message,certs[1])
        e.linkback=self.client_server
        HTTPServer.__init__(self, _client_address,e)
    
        """tcontext=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        tcontext.set_ciphers("HIGH")
        tcontext.options=tcontext.options|ssl.OP_SINGLE_DH_USE|ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
        tcontext.load_cert_chain(self.crappyssl.name,certs[0])
        self.socket=tcontext.wrap_socket(tcontext)"""


class client_init(object):
    config_path=None
    client=None
    server=None
    
    def __init__(self,_configpath,_port=None):
        self.config_path=path.expanduser(_configpath)
        init_config_folder(self.config_path)
        if check_certs(self.config_path+"client_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(self.config_path+"client_cert")
            logging.debug("Certificate generation complete")
        with open(self.config_path+"client_cert"+".priv", 'rb') as readinprivkey:
            priv_cert=readinprivkey.read()
        with open(self.config_path+"client_cert"+".pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()

        with open(self.config_path+"client", 'r') as readclient:
            try:
                _client=readclient.readline().split("/")
            except Exception as e:
                print("Configuration error in {}".format(self.config_path+"client"))
                raise(e)
            
        with open(self.config_path+"message", 'r') as readinmes:
            message=readinmes.read()
        if None in [priv_cert,pub_cert,_client,message]:
            raise(Exception("missing"))
        
        if _port is not None:
            _port=int(_port)
        elif len(_client)>=2:
            _port=int(_client[1])
        else:
            _port=client_port
        self.client=client_client(_client[0],hashlib.sha256(pub_cert).hexdigest(),_port)
        self.server=http_client_server(("0.0.0.0",_port),(priv_cert,pub_cert),_client[0],message)

    def serve_forever_block(self):
        self.server.serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()
    
        
##
def signal_handler(_signal, frame):
  sys.exit(0)


if __name__ ==  "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv)==1:
        cm=client_init(default_configdir)
    else:
        cm=client_init(default_configdir,sys.argv[1])
    logging.debug("start server")
    cm.serve_forever_nonblock()
    logging.debug("server started")
    while True:
        inp=input("Enter command, seperate by \"/\":\n")
        if inp=="":
            break
        parsed=inp.split("/")
        if len(parsed)==1:
            print("Missing servername")
            continue
        try:
            func=type(cm.client).__dict__[str(parsed[0])]
            url=parsed[1].split(":",1)
            resp=func(cm.client,url,*parsed[2:])
            print(resp.read().decode("utf8"))
        except Exception as e:
            print("Error: ")
            #print(url)
            print(type(e).__name__)
            print(e)
        
