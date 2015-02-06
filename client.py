#! /usr/bin/env python3

#import SSL as ssln
#from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import socketserver
import logging
import ssl
import sys,signal,threading
import traceback
import os
from os import path

from common import success,error,server_port,check_certs,generate_certs,init_config_folder,default_configdir,certhash_db,default_sslcont,parse_response,dhash,VALNameError,isself,check_name,dhash_salt,gen_passwd_hash





class client_client(object):
    name=None
    cert_hash=None
    port=None
    sslconts=None
    sslcontc=None
    hashdb=None
    #pwcache={}
    
    def __init__(self,_name,pub_cert_hash,_certdbpath,_links):
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.hashdb=certhash_db(_certdbpath)
        self.sslcont=default_sslcont()
        self.links=_links

    def do_request(self,con,requeststr,dparam):
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        val=self.hashdb.certhash_as_name(dhash(pcert))
        #print(dparam)
        if dparam["certname"] is not None and dparam["certname"]!=val:
            raise(VALNameError)
        con.putrequest("GET", requeststr)
        #if pwhash is not None:
        
        if dparam["spwhash"] is not None:
            con.putheader("spwhash",dparam["spwhash"])
        #elif self.host+"/"+self.port in self.pwcache:
            
        con.endheaders()
        
        resp=parse_response(con.getresponse())
        con.close()
        return resp[0],resp[1],val

    def show(self):
        return (True,(self.name,self.cert_hash
                ,str(self.links["server"].socket.getsockname()[1])),isself)
    
    def register(self,server_addr,dparam):
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.links["server"].socket.getsockname()[1]),dparam)
    
    def get(self,server_addr,_name,_hash,dparam):
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con,"/get/{}/{}".format(_name,_hash),dparam)
    
    def connect(self,server_addr,_name,_hash,dparam):
        temp=self.get(server_addr,_name,_hash,dparam)
        return temp

    def gethash(self,_addr):
        _addr=_addr.split(":")
        if len(_addr)==1:
            _addr=(_addr[0],server_port)
        con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        con.close()
        return (True,(dhash(pcert),pcert),None)
        
  
    def unparsedlistnames(self,server_addr,dparam):
        server_addr=server_addr.split(":")
        if len(server_addr)==1:
            server_addr=(server_addr[0],server_port)
        con=client.HTTPSConnection(server_addr[0],server_addr[1],context=self.sslcont)
        return self.do_request(con, "/listnames",dparam)

    
    def listnames(self,server_addr,dparam):
        temp=self.unparsedlistnames(server_addr,dparam)
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
    
    def getservice(self,client_addr,_service,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/get/{}".format(_service),dparam)

    def registerservice(self,client_addr,_service,_port,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
            #_sslcontext.verify_flag=ssl.VERIFY_DEFAULT
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/register/{}/{}".format(_service,_port))

    def listservices(self,client_addr,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        return self.do_request(con, "/listservices",dparam)
    
    def info(self,client_addr,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        temp=self.do_request(con,  "/info",dparam)
        if temp[0]==True:
            return temp[0],temp[1].split("/",3),temp[2]
        else:
            return temp
        
    def priodirect(self,client_addr,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        temp=self.do_request(con,  "/prio",dparam)
        return temp

    def capabilities(self,client_addr,dparam):
        client_addr=client_addr.split(":")
        if len(client_addr)==1:
            return (False,"no port specified",isself)
        con=client.HTTPSConnection(client_addr[0],client_addr[1],context=self.sslcont)
        temp=self.do_request(con,  "/cap",dparam)
        if temp[0]==True:
            return temp[0],temp[1].split(",",3),temp[2]
        else:
            return temp
        
    #includes update priority
    def check(self,server_addr,_name,_hash,dparam):
        temp=self.get(server_addr,_name,_hash,dparam)
        if temp[0]==False:
            return temp
        temp=self.priodirect(temp[1],dparam)
        if temp[0]==False:
            return temp
        if self.hashdb.exist(_name,_hash)==True:
            self.hashdb.changepriority(_name,_hash)
        return temp
    
    #update db entry
    def update(self,server_addr,_name,_hash,dparam):
        temp=self.get(server_addr,_name,_hash,dparam)
        if temp[0]==False or self.hashdb.exist(_name,_hash)==False:
            return temp
        temp=self.priodirect(temp[1],dparam)
        if temp[0]==False or self.hashdb.changepriority(_name,_hash,temp[1])==False:
            return temp
        
        temp=self.info(temp[1],dparam)
        
        if temp[0]==False:
            return temp
        _sp=temp[1].split(3)
        if len(_sp)==3:
            if self.hashdb.changetype(_name,_hash,_sp[0])==True:
                return True,"update successful",None
            else:
                return False,temp[1],None
        return False,temp[1],None
                
        
    #local management
    def addname(self,_name,dparam):
        temp=self.hashdb.addname(_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    def addhash(self,*args):
        if len(args)==3:
            _name,_certhash,dparam=args
        else:
            server_addr,_name,_certhash,dparam=args
        
        temp=self.hashdb.addhash(_name,_certhash)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)
        
    def deljusthash(self,_certhash,dparam):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)
        
    def delhash(self,_name,_certhash,dparam):
        temp=self.hashdb.delhash(_certhash,_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    def delname(self,_name,dparam):
        temp=self.hashdb.delname(_name)
        if temp==True:
            return (True,"success",isself)
        else:
            return (False,"error",isself)

    #search
    def searchhash(self,_certhash,dparam):
        temp=self.hashdb.certhash_as_name(_certhash)
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)
    
    def listhashes(self,_name,dparam):
        temp=self.hashdb.listcerts(_name)
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)
    
    def listnamesl(self,dparam):
        temp=self.hashdb.listnames()
        if temp is None:
            return(False, "error",isself)
        else:
            return (True,temp,isself)


###server on client
    
class client_server(object):
    capabilities="basic" #comma seperate
    
    info=None
    scntype="client"
    priority=None
    spmap={}
    def __init__(self,_name,_priority,_msg):
        #self.name=_name
        if len(_name)==0:
            logging.debug("Name empty")
            _name="<noname>"
        
        #self.msg=_msg
        if len(_msg)==0:
            logging.debug("Message empty")
            _msg="<empty>"
        self.info="{}{}/{}&{}".format(success,self.scntype,_name,_msg)
        self.capabilities="{}{}".format(success,self.capabilities)
        self.priority="{}{}".format(success,_priority)
    
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

    def info(self,_addr):
        return self.info
    
    def cap(self,_addr):
        return self.capabilities
    
    def prio(self,_addr):
        return self.priority
    
class client_handler(BaseHTTPRequestHandler):
    links=None
    validactions=["info","get","register","listservices","cap","prio"]
    clientactions=["register","get","connect","gethash", "show","addhash","deljusthash","delhash","listhashes","searchhash","listnames","listnamesl","unparsedlistnames","getservice","registerservice","listservices","info","check","update","priodirect"]
    handle_localhost=False
    handle_remote=False
    cpwhash=None
    spwhash=None
    salt=None
    icon=b""
    
    def index(self):
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        self.wfile.write(b"TODO")

    def check_cpw(self,dparam):
        if self.cpwhash is None:
            return True
        if "cpwhash" in self.headers:
            if dhash_salt(self.headers["cpwhash"],self.salt)==self.cpwhash:
                return True
        elif "cpwhash" in dparam:
            if dhash_salt(dparam["cpwhash"],self.salt)==self.cpwhash:
                return True
        return False

    def check_spw(self):
        if self.spwhash is None:
            return True
        if "spwhash" in self.headers:
            if dhash_salt(self.headers["spwhash"],self.salt)==self.spwhash:
                return True
        
        return False
    
    def handle_client(self,_cmdlist,dparam):
        _cmdlist+=[dparam,]
        if self.handle_remote==False and not self.client_address[0] in ["localhost","127.0.0.1","::1"]:
            self.send_error(401,"insufficient permissions")
            return
        if self.check_cpw(dparam)==False:
            self.send_error(401,"insufficient permissions")            
            return
        
        try:
            func=type(self.links["client"]).__dict__[_cmdlist[0]]
            response=func(self.links["client"],*_cmdlist[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                #helps against ssl failing about empty string (EOF)
                st=str(e)+"\n\n"+str(traceback.format_tb(e))
                if len(st)>0:
                    self.send_error(500,st)
                else:
                    self.send_error(500,"unknown")
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
         # add address to _cmdlist
        _cmdlist+=[self.client_address,]
        
        if self.check_spw()==False:
            self.send_error(401,"insufficient permissions")            
            return
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
        if self.path=="/favicon.ico":
            self.wfile.write(self.icon)
            return
        pos_param=self.path.find("?")
        dparam={"certname":None,"cpwhash":None,"spwhash":None}
        if pos_param!=-1:
            _cmdlist=self.path[1:pos_param].split("/")
            tparam=self.path[pos_param:].split("&")
            for elem in tparam:
                elem=elem.split("=")
                if len(elem)!=2:
                    self.send_error(400,"invalid key/value pair\n{}".format(elem))
                    return
                
                
        else:
            _cmdlist=self.path[1:].split("/")
        if _cmdlist[0]=="":
            self.index()
            return
        if self.handle_localhost==True and _cmdlist[0]=="do" and _cmdlist[1] in self.clientactions:
            self.handle_client(_cmdlist[1:],dparam) #remove do
        elif _cmdlist[0]!="do" and _cmdlist[0] in self.validactions:
            self.handle_server(_cmdlist) #,dparam)
        else:
            self.send_error(400,"invalid action")
            return
     

    """def do_POST(self):
        _cmdlist=???.split("&")
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
            return"""
            
        
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
    
    def __init__(self,**kwargs):
        self.config_path=path.expanduser(kwargs["config"])
        if self.config_path[-1]==os.sep:
            self.config_path=self.config_path[:-1]
        _cpath="{}{}{}".format(self.config_path,os.sep,"client")
        init_config_folder(self.config_path,"client")
        
        client_handler.salt=os.urandom(4)
        port=kwargs["port"]
        if kwargs["local"] is not None:
            client_handler.handle_localhost=True
        elif kwargs["cpwhash"] is not None:
            if kwargs["remote"] is not None:
                client_handler.handle_remote=True       
            client_handler.handle_localhost=True
            client_handler.cpwhash=dhash_salt(kwargs["cpwhash"],client_handler.salt)
        elif kwargs["cpwfile"] is not None:
            if kwargs["remote"] is not None:
                client_handler.handle_remote=True
            client_handler.handle_localhost=True
            op=open("r")
            client_handler.cpwhash=gen_passwd_hash(op.readline())
            op.close()
            
        if kwargs["spwhash"] is not None:
            client_handler.spwhash=dhash_salt(kwargs["spwhash"],client_handler.salt)
        elif kwargs["spwfile"] is not None:
            op=open("r")
            client_handler.spwhash=gen_passwd_hash(op.readline())
            op.close()
        
        with open("favicon.ico", 'rb') as faviconr:
            client_handler.icon=faviconr.read()
        if check_certs(_cpath+"_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logging.debug("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()

        with open(_cpath+"_name", 'r') as readclient:
            _name=readclient.readline()
        with open(_cpath+"_message", 'r') as readinmes:
            _message=readinmes.read()
            if _message[-1] in "\n":
                _message=_message[:-1]
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)
        #if check_name

        
        if port is not None:
            port=int(port)
        elif len(_name)>=2:
            port=int(_name[1])
        else:
            port=0
            
        self.links["client_server"]=client_server(_name[0],kwargs["priority"],_message)
        client_handler.links=self.links
        self.links["server"]=http_client_server(("0.0.0.0",port),_cpath+"_cert")
        self.links["client"]=client_client(_name[0],dhash(pub_cert),self.config_path+os.sep+"certdb.sqlite",self.links)

    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()

    def cmd(self):
        
        print(*self.links["client"].show()[1],sep="/")
        while True:
            inp=input("Enter command, seperate by \"/\"\nEnter parameters by closing command with \"?\" and\nadding key1=value1&key2=value2 key/value pairs:\n")
            if inp=="":
                break

            unparsed=inp.strip(" ").rstrip(" ")
            if unparsed[:5]=="hash/":
                print(dhash(unparsed[6:]))
                continue
            dparam={"certname":None,"cpwhash":None,"spwhash":None}
            pos_param=unparsed.find("?")
            if pos_param!=-1:
                parsed=unparsed[:pos_param].split("/")
                tparam=unparsed[pos_param+1:].split("&")
                for elem in tparam:
                    elem=elem.split("=")
                    if len(elem)!=2:
                        self.send_error(400,"invalid key/value pair\n{}".format(elem))
                        return
                    dparam[elem[0]]=elem[1]
            else:
                parsed=unparsed.split("/")
            parsed+=[dparam,]
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
def paramhelp():
    print(\
"""
possible parameters:
port: port
blank: can command server without pw (localhost only), higher preference than pwhash
(s/c)pwhash: sha256 hash of pw, higher preference than pwfile
(s/c)pwfile: file with password (cleartext)
s: protect input
c: protect client control
remote: lift limit localhost

""")

def cmdhelp():
    print(\
"""
### cmd-commands ###


""")
    
def signal_handler(_signal, frame):
  sys.exit(0)
  
#remoteactions=["register","","","listnames"]
if __name__ ==  "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    d={"config":default_configdir,
       "port":None,
       "cpwhash":None,
       "cpwfile":None,
       "spwhash":None,
       "spwfile":None,
       "priority":"20",
       "local":None,
       "remote":None}
    
    if len(sys.argv)>1:
        tparam=()
        for elem in sys.argv:
            elem=elem.strip("-")
            if elem in ["help","h"]:
                paramhelp()
                sys.exit(0)
            else:
                tparam=elem.split("=")
                if len(tparam)==1:
                    tparam=elem.split(":")
                if  len(tparam)==1:
                    continue
                d[tparam[0]]=tparam[1]
            
    cm=client_init(**d)
        
    #client_handler.handle_localhost=True
    logging.debug("start server")
    cm.serve_forever_nonblock()
    logging.debug("server started")
    cm.cmd()
