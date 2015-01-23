#! /usr/bin/env python3

#import SSL as ssln
#from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import socketserver
import logging
import ssl
import sys,signal,threading
import os
from os import path

from common import success,error,server_port,check_certs,generate_certs,init_config_folder,default_configdir,certhash_db,default_sslcont,parse_response,dhash,VALNameError,isself





class client_client(object):
    name=None
    cert_hash=None
    port=None
    sslconts=None
    sslcontc=None
    hashdb=None
    
    def __init__(self,_name,pub_cert_hash,_certdbpath,_links):
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.hashdb=certhash_db(_certdbpath)
        self.sslcont=default_sslcont()
        self.links=_links

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
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.links["server"].socket.getsockname()[1],_certname))
    
    def get(self,server_addr,_name,_hash,_certname=None):
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/get/{}/{}".format(_name,_hash),_certname)
    
    def connect(self,server_addr,_name,_hash,_certname=None):
        temp=self.get(server_addr,_name,_hash,_certname)
        return temp

    def show(self):
        return (True,(self.name,self.cert_hash
                ,str(self.links["server"].socket.getsockname()[1])),isself)

    def gethash(self,_addr):
        _addr=_addr.split(":")
        if len(_addr)==1:
            _addr=(_addr[0],server_port)
        con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        con.close()
        return (True,(dhash(pcert),pcert),None)
        
    def addhash(self,_name,_certhash):
        temp=self.hashdb.addhash(_name,_certhash)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)
    
    def deljusthash(self,_certhash):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)
        
    def delhash(self,_name,_certhash):
        temp=self.hashdb.delhash(_certhash,_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    def addname(self,_name):
        temp=self.hashdb.addname(_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    def delname(self,_name):
        temp=self.hashdb.delname(_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    def searchhash(self,_certhash):
        temp=self.hashdb.certhash_as_name(_certhash)
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)
    
    def listhashes(self,_name):
        temp=self.hashdb.listcerts(_name)
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)
    
    def listnamesl(self):
        temp=self.hashdb.listnames()
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)
    
    def listnames(self,server_addr,_certname=None):
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con, "/listnames",_certname)

    def parsedlistnames(self,server_addr,_certname=None):
        server_addr=server_addr.split(":")
        temp=self.listsnames(server_addr,_certname)
        if temp[0]==False:
            return temp
        temp2=[]
        for line in temp[1].split("\n"):
            _split=line.split("/")
            if len(_split)!=2:
                logging.debug("invalid element:\n{}".format(line))
                continue
            if _split[1]==self.cert_hash:
                temp2+=[(_split[0],_split[1],isself),]
            else:
                temp2+=[(_split[0],_split[1],self.hashdb.certhash_as_name(_split[1])),]
        return (temp[0],temp2,temp[2])

    def getservice(self,client_addr,_service,_certname=None):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/get/{}".format(_service),_certname)

    def registerservice(self,client_addr,_service,_port,_certname=None):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
            #_sslcontext.verify_flag=ssl.VERIFY_DEFAULT
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/register/{}/{}".format(_service,_port))

    def listservices(self,client_addr,_certname=None):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/listservices",_certname)
    
    def info(self,client_addr,_certname=None):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con,  "/info",_certname)
    
class client_server(object):
    name=""
    msg=""
    spmap={}
    def __init__(self,_name,_msg):
        self.name=_name
        if len(_name)==0:
            logging.debug("Name empty")
            self.name="noname"
        
        self.msg=_msg
        if len(_msg)==0:
            logging.debug("Message empty")
            self.msg="<empty>"
    def info(self,_addr):
        #print(self,_addr)
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
    links=None
    validactions=["info","get","register","listservices"]
    clientactions=["register","get","connect","gethash", "show","addhash","deljusthash","delhash","listhashes","searchhash","listnamesl","parsedlistnames","getservice","registerservice","listservices","info"]
    handle_localhost=False
    
    def index(self):
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        self.wfile.write("TODO")

    def handle_client(self,_cmdlist):
        if not self.client_address[0] in ["localhost","127.0.0.1","::1"]:
            self.send_error(403,"insufficient permissions")
        
        try:
            func=type(self.links["client"]).__dict__[_cmdlist[0]]
            response=func(self.links["client"],*_cmdlist[1:-1]) # remove address from _cmdlist
        except Exception as e:
            self.send_error(500,str(e))
            return
        if response[0]==False:
            #helps against ssl failing about empty string (EOF)
            if len(response[1])>0:
                self.send_error(400,response[1])
            else:
                self.send_error(400,"unknown")
        else:
            self.send_response(200)
            self.send_header('Content-type',"text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(response[1])>0:
                if type(response[1]) is [] or type(response[1]) is ():
                    for elem in response[1]:
                        self.wfile.write(bytes(elem+"\n","utf8"))
                else:
                    self.wfile.write(bytes(str(response[1]),"utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))

    def handle_server(self,_cmdlist):
        try:
            func=type(self.links["client_server"]).__dict__[_cmdlist[0]]
            response=func(self.links["client_server"],*_cmdlist[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                self.send_error(500,str(e))
            else:
                self.send_error(500,"server error")
            return
        
        respparse=response.split("/",1)
        if respparse[0]=="error":
            #helps against ssl failing about empty string (EOF)
            if len(respparse[1])>0:
                self.send_error(400,respparse[1])
            else:
                self.send_error(400,"unknown")
        else:
            self.send_response(200)
            self.send_header('Content-type',"text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(respparse[1])>0:
                self.wfile.write(bytes(respparse[1],"utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))
            
    def do_GET(self):
        _cmdlist=self.path[1:].split("/")
        if _cmdlist[0]=="":
            self.index()
            return
        _cmdlist=_cmdlist+[self.client_address,]
        if self.handle_localhost==True and _cmdlist[0]=="do" and _cmdlist[1] in self.clientactions:
            self.handle_client(_cmdlist[1:]) #remove do
        elif _cmdlist[0]!="do" and _cmdlist[0] in self.validactions:
            self.handle_server(_cmdlist)
        else:
            self.send_error(400,"invalid action")
            return
            
        
class http_client_server(socketserver.ThreadingMixIn,HTTPServer,client_server):
        
    def __init__(self, _client_address,certfpath):
        HTTPServer.__init__(self, _client_address,client_handler)
        self.sslcont=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.sslcont.set_ciphers("HIGH")
        self.sslcont.options=self.sslcont.options|ssl.OP_SINGLE_DH_USE|ssl.OP_NO_COMPRESSION
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv")
        self.socket=self.sslcont.wrap_socket(self.socket)
        


class client_init(object):
    config_path=None
    links={}
    #localactions=["addname","delname","addhash","delhash","listnamesl","listhashes","searchhash"]
    
    def __init__(self,_configpath,_port=None):
        self.config_path=path.expanduser(_configpath)
        init_config_folder(self.config_path)
        if check_certs(self.config_path+"client_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(self.config_path+"client_cert")
            logging.debug("Certificate generation complete")
        with open(self.config_path+os.sep+"client_cert"+".priv", 'rb') as readinprivkey:
            priv_cert=readinprivkey.read()
        with open(self.config_path+"client_cert"+".pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()

        with open(self.config_path+os.sep+"client", 'r') as readclient:
            try:
                _client=readclient.readline().split("/")
            except Exception as e:
                print("Configuration error in {}".format(self.config_path+"client"))
                raise(e)
        with open(self.config_path+os.sep+"message", 'r') as readinmes:
            message=readinmes.read()
            if message[-1] in "\n":
                message=message[:-1]
        if None in [priv_cert,pub_cert,_client,message]:
            raise(Exception("missing"))
        
        if _port is not None:
            _port=int(_port)
        elif len(_client)>=2:
            _port=int(_client[1])
        else:
            _port=0
        
        self.links["client_server"]=client_server(_client[0],message)
        client_handler.links=self.links
        self.links["server"]=http_client_server(("0.0.0.0",_port),self.config_path+"client_cert")
        self.links["client"]=client_client(_client[0],dhash(pub_cert),self.config_path+os.sep+"certdb.sqlite",self.links)

    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()

    def cmd(self):
        
        print(*self.links["client"].show()[1],sep="/")
        while True:
            inp=input("Enter command, seperate by \"/\":\n")
            if inp=="":
                break
            parsed=inp.strip(" ").rstrip(" ").split("/")

            try:
                func=type(self.links["client"]).__dict__[str(parsed[0])]
                resp=func(self.links["client"],*parsed[1:])
                if resp[2] is None:
                    print("Unverified")
                elif resp[2] is isself:
                    print("Is own client")
                else:
                    print("Verified as: "+resp[2])
                if resp[0]==False:
                    print("Error:\n{}".format(resp[1]))
                else:
                    print("Success:\n{}".format(resp[1]))
            except Exception as e:
                print("Error: ")
                #print(url)
                print(type(e).__name__)
                print(e)
                print(parsed)
                #print(e.printstacktrace())
    
        
##
def signal_handler(_signal, frame):
  sys.exit(0)


#remoteactions=["register","","","listnames"]
if __name__ ==  "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv)==1:
        cm=client_init(default_configdir)
    else:
        cm=client_init(default_configdir,sys.argv[1])
        
    #client_handler.handle_localhost=True
    logging.debug("start server")
    cm.serve_forever_nonblock()
    logging.debug("server started")
    cm.cmd()
