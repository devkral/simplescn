#! /usr/bin/env python3

#import SSL as ssln
#from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import logging
import ssl
import sys,signal,threading
import os
from os import path

from common import success,error,server_port,client_port,check_certs,generate_certs,init_config_folder,default_configdir,certhash_db,default_sslcont,parse_response,dhash,VALNameError,isself





class client_client(object):
    name=None
    cert_hash=None
    port=None
    sslconts=None
    sslcontc=None
    hashdb=None
    
    
    def __init__(self,_name,_port,pub_cert_hash,_certdbpath):
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.port=_port
        self.hashdb=certhash_db(_certdbpath)
        #self.certdir=_certdir
        #self.sslconts.verify_flags=ssl.VERIFY_DEFAULT
        
        self.sslcont=default_sslcont()

    def do_request(self,con,requeststr,name=None):
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        val=self.hashdb.certhash_as_name(dhash(pcert))
        if name is not None and name!=val:
            raise(VALNameError)
        con.putrequest("GET", requeststr)
        #con.putheader("test")
        con.endheaders()
        
        resp=parse_response(con.getresponse())
        con.close()
        return resp[0],resp[1],val
        
    def register(self,server_addr,_certname=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.port),_certname)
    
    def get(self,server_addr,_name,_hash,_certname=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/get/{}/{}".format(_name,_hash),_certname)
    
    def connect(self,server_addr,_name,_hash,_certname=None):
        temp=self.get(server_addr,_name,_hash,_certname)
        return temp    
    
    def addcerthash(self,_name,_certhash): #TODO: verify server
        temp=self.hashdb.addhash(_name,_certhash)
        if temp[0]==True:
            return (True,"success",None)
        else:
            return (False,"error",None)
    
    def delcerthash(self,_name,_certhash):
        temp=self.hashdb.delhash(_name,_certhash)
        if temp[0]==True:
            return (True,"success",None)
        else:
            return (False,"error",None)

    def addname(self,_name):
        temp=self.hashdb.addname(_name)
        if temp[0]==True:
            return (True,"success",None)
        else:
            return (False,"error",None)

    def delname(self,_name):
        temp=self.hashdb.delname(_name)
        if temp[0]==True:
            return (True,"success",None)
        else:
            return (False,"error",None)
    
    def listnames(self,server_addr,_certname=None):
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con, "/listnames",_certname)

    def parsedlistnames(self,server_addr,_certname=None):
        temp=self.listnames(server_addr,_certname)
        if temp[0]==False:
            return temp
        temp2=[]
        for line in temp[1].split("\n"):
            _split=line.split("/")
            if len(_split)!=2:
                logging.debug("invalid element: {}".format(line))
                continue
            if _split[1]==self.cert_hash:
                temp2+=[(_split[0],_split[1],isself),]
            else:
                temp2+=[(_split[0],_split[1],self.hashdb.certhash_as_name(_split[1])),]
        
        return (temp[0],temp2,temp[2])

    def getservice(self,client_addr,_service,_certname=None):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/get/{}".format(_service),_certname)

    def registerservice(self,client_addr,_service,_port,_certname=None):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
            #_sslcontext.verify_flag=ssl.VERIFY_DEFAULT
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/register/{}/{}".format(_service,_port))

    def listservices(self,client_addr,_certname=None):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/listservices",_certname)
    
    def info(self,client_addr,_certname=None):
        if len(client_addr)==1:
            client_addr=(client_addr[0],client_port)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con,  "/info",_certname)
    
class client_server(object):
    name=""
    msg=""
    spmap={}
    def __init__(self,_name,_msg):
        
        self.name=_name
        if len(_name)==0:
            self.name="empty"
        
        self.msg=_msg
        if len(_msg)==0:
            self.msg="empty"
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
        if len(temp)==0:
            return "{}empty".format(success)
        return success+temp
    def register(self,_service,_port,_addr):
        if _addr[0] in ["localhost","127.0.0.1","::1"]:
            self.spmap[_service]=_port
            return success
        return error
class client_handler(BaseHTTPRequestHandler):
    linkback=None
    validactions=["info","get","register","listservices"]

    
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
    
    
    def __init__(self, _client_address,name,message,certfpath):
        e=client_handler
        self.client_server=client_server(name,message)
        e.linkback=self.client_server
        HTTPServer.__init__(self, _client_address,e)
    
        self.sslcont=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.sslcont.set_ciphers("HIGH")
        self.sslcont.options=self.sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_NO_COMPRESSION
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv")
        self.socket=self.sslcont.wrap_socket(self.socket)
        
    #def get_request(self):
    #    tsocket,address=self.socket.accept()
    #    if False and address=="127.0.0.1":
    #        return (tsocket,address)
    #    else:
    #        return (self.sslcont.wrap_socket(tsocket),address)


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
        self.client=client_client(_client[0],_port,dhash(pub_cert),self.config_path+os.sep+"certdb.sqlite")
        self.server=http_client_server(("0.0.0.0",_port),_client[0],message,self.config_path+"client_cert")

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
            if resp[2] is None:
                print("Unverified")
            else:
                print("Verified as: "+resp[2])
            if resp[0]==False:
                print("Error: {}"+resp[1])
            else:
                print(resp[1])
        except Exception as e:
            print("Error: ")
            #print(url)
            print(type(e).__name__)
            print(e)
            #print(e.printstacktrace())
        
