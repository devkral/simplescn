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
import socket
import os
from os import path

from common import success,error,server_port,check_certs,generate_certs,init_config_folder,default_configdir,certhash_db,default_sslcont,parse_response,dhash,VALNameError,VALHashError,isself,check_name,dhash_salt,gen_passwd_hash,commonscn,sharedir,scnparse_url,AddressFail



class client_client(object):
    name=None
    cert_hash=None
    sslconts=None
    sslcontc=None
    hashdb=None
    links=None
    #isself=isself
    validactions={"register","get","connect","check","check_direct","gethash", "show","addhash","deljusthash","delhash","listhashes","searchhash","addname","delname","updatename","listnames","listnodenames","listall","unparsedlistnames","getservice","registerservice","listservices","info","check","check_direct","prioty_direct","prioty","setpriority","delservice","ask"}
    #pwcache={}
    
    def __init__(self,_name,pub_cert_hash,_certdbpath,_links):
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.hashdb=certhash_db(_certdbpath)
        self.sslcont=default_sslcont()
        self.links=_links

    def do_request(self,_addr,requeststr,dparam,usecache=False,forceport=False):
        _addr=scnparse_url(_addr,force_port=forceport)
        con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        if dhash(pcert)==self.cert_hash:
            val=isself
        elif dparam["certhash"] is not None and dparam["certhash"]!=dhash(pcert):
            raise(VALHashError)
        elif dparam["nohashdb"] is None:
            val=self.hashdb.certhash_as_name(dhash(pcert))
            #print(dparam)
            if dparam["certname"] is not None and dparam["certname"]!=val:
                raise(VALNameError)
            if val=="isself":
                raise(VALNameError)

        if dparam["tdestname"] is not None and dparam["tdesthash"] is not None:
            
            con.putrequest("CONNECT", "/{}/{}".format(dparam["tdestname"],dparam["tdesthash"]))
            pheaders={}
            if dparam["tpwhash"] is not None:
                pheaders["tpwhash"]=dparam["tpwhash"]
            #con.putheader("tdestname",dparam["tdestname"])
            #con.putheader("tdesthash",dparam["tdesthash"])

            if dparam["spwhash"] is not None:
                pheaders["spwhash"]=dparam["spwhash"]
            if dparam["cpwhash"] is not None:
                con.putheader("cpwhash",dparam["cpwhash"])
            con.set_tunnel(requeststr,pheaders)
        else:
            con.putrequest("GET", requeststr)
        
            if dparam["spwhash"] is not None:
                con.putheader("spwhash",dparam["spwhash"])
            if dparam["cpwhash"] is not None:
                con.putheader("cpwhash",dparam["cpwhash"])


        if usecache==False:
            con.putheader("Cache-Control", "no-cache")
        
        con.endheaders()
        
        resp=parse_response(con.getresponse())

        con.close()
        
        if dparam["nohashdb"] is not None:
            #here the order is changed so use split instead of rsplit
            temp=resp[1].split("/",1)
            if len(temp)==2:
                if temp[0]=="isself":
                    val=isself
                else:
                    #val is in different order
                    val=temp[0]
                #reorder message part to middle
                return (resp[0],temp[1],val)
            else:
                return (resp[0],resp[1],dhash(pcert))
        else:    
            return resp[0],resp[1],val

    def show(self,dparam):
        return (True,(self.name,self.cert_hash,
                str(self.links["server"].socket.getsockname()[1])),isself)
    
    def register(self,server_addr,dparam):
        return self.do_request(server_addr,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.links["server"].socket.getsockname()[1]),dparam)
    
    def get(self,server_addr,_name,_hash,dparam):
        temp=self.do_request(server_addr,"/get/{}/{}".format(_name,_hash),dparam)
        try:
            address,port=temp[1].rsplit(":",1)
        except ValueError:
            return (False,"splitting not possible",temp[1])
        try:
            temp=(temp[0],(address,int(port)),temp[2])
            if temp[1][1]<1:
                return (False,"port <1",temp[1])
        except ValueError:
            return (False,"port not a number",temp[1])
        return temp
    
    def gethash(self,_addr,dparam):
        _addr=_addr.split(":")
        if len(_addr)==1:
            _addr=(_addr[0],server_port)
        try:
            con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
            con.connect()
            pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            con.close()
            return (True,(dhash(pcert),pcert),None)
        except ssl.SSLError:
            return (False,"server speaks no tsl 1.2",None)
        except Exception:
            return (False,"server does not exist",None)

    def ask(self,server_addr,dparam):
        _ha=self.gethash(server_addr,dparam)
        if _ha[0]==False:
            return _ha
        temp=self.hashdb.certhash_as_name(_ha[1][0])
        return (True,(_ha[1][0],temp),isself)


        
    def unparsedlistnames(self,server_addr,dparam):
        return self.do_request(server_addr, "/listnames",dparam,usecache=True)

    
    def listnames(self,server_addr,dparam):
        temp=self.unparsedlistnames(server_addr,dparam)
        if temp[0]==False:
            return temp
        temp2=[]
        if temp[1]!="empty":
            for line in temp[1].split("\n"):
                _split=line.split("/")
                if len(_split)!=2:
                    logging.debug("invalid element:\n{}".format(line))
                    continue
                if _split[0]=="isself":
                    logging.debug("invalid name:\n{}".format(line))
                    continue
                if _split[1]==self.cert_hash:
                    temp2+=[(_split[0],_split[1],isself),] 
                else:
                    temp2+=[(_split[0],_split[1],self.hashdb.certhash_as_name(_split[1])),]
        return (temp[0],temp2,temp[2])
    
    def getservice(self,client_addr,_service,dparam):
        return self.do_request(client_addr, "/getservice/{}".format(_service),dparam)

    def registerservice(self,*args):
        if len(args)==3:
            _servicename,_port,dparam=args
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==4:
            client_addr,_servicename,_port,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        
        temp= self.do_request(client_addr, "/registerservice/{}/{}".format(_servicename,_port),dparam,forceport=True)
        if len(args)==3 and temp[2] is not isself:
            raise(VALNameError)
        return temp

    def delservice(self,*args):
        if len(args)==2:
            _servicename,dparam=args
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==3:
            client_addr,_servicename,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        
        temp= self.do_request(client_addr, "/delservice/{}".format(_servicename),dparam,forceport=True)
        if len(args)==3 and temp[2] is not isself:
            raise(VALNameError)
        return temp


    def listservices(self,*args):
        if len(args)==1:
            dparam=args[0]
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            client_addr,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        temp=self.do_request(client_addr, "/listservices",dparam,forceport=True)
        if temp[0]==False:
            return temp
        temp2=[]
        if temp[1]!="empty":
            for elem in temp[1].split("\n"):
                temp2+=[elem.rsplit("&",1),]
        return (temp[0],temp2,temp[2])
    
    def info(self,*args): # _addr,dparam):
        if len(args)==1:
            dparam=args[0]
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            _addr,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        _hash=self.gethash(_addr,dparam)
        if _hash[0]==False:
            return (False,"hash retrieval failed",isself)
        _tinfo=self.do_request(_addr,  "/info",dparam,forceport=True)
        if _tinfo[0]==True:
            _tinfolist=_tinfo[1].split("/",3)
            if _tinfolist[2]!=_hash[1]:
                (False,"hash missmatch",isself)
            return (True,_tinfolist,_tinfo[2])
            
        else:
            return _tinfo

            
    def prioty_direct(self,*args):
        if len(args)==1:
            dparam=args[0]
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            _addr,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        temp=self.do_request(_addr,  "/prioty",dparam,forceport=True)
        return temp

    def prioty(self,server_addr,_name,_hash,dparam):
        temp=self.get(server_addr,_name,_hash,dparam)
        if temp[0]==False:
            return temp
        return self.prioty_direct(temp[1])


    def setpriority(self,*args):
        if len(args)==2:
            _priority,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        if type(_priority).__name__=="str" and _priority.isdecimal()==False:
            return (False,"no integer",isself)
        elif type(_priority).__name__=="str":
            _priority=int(_priority)
        elif type(_priority).__name__!="int":
            return (False,"unsupported datatype",isself)
        if _priority<0 or _priority>100:
            return (False,"out of range",isself)
        
        self.links["server"].priority=_priority
        self.links["server"].update_prioty()
        return (True,"priority",isself)

    def capabilities(self,_addr,dparam):
        temp=self.do_request(_addr,  "/cap",dparam,forceport=True)
        if temp[0]==True:
            return temp[0],temp[1].split(",",3),temp[2]
        else:
            return temp

    #check if _addr is reachable and update priority
    def check_direct(self,_addr,_name,_hash,dparam):
        temp=self.prioty_direct(_addr,dparam)
        if temp[0]==False:
            return temp
        if self.hashdb.exist(_name,_hash)==True:
            self.hashdb.changepriority(_name,_hash,temp[1][0])
            self.hashdb.changetype(_name,_hash,temp[1][1])
        return temp

    
    #check if node is reachable and update priority
    def check(self,server_addr,_name,_hash,dparam):
        temp=self.get(server_addr,_name,_hash,dparam)
        if temp[0]==False:
            return temp
        return self.check_direct(temp[1],_name,_hash,dparam)

        
                
        
    #local management
    def addname(self,_name,dparam):
        temp=self.hashdb.addname(_name)
        if temp==True:
            return (True,success,isself)
        else:
            return (False,error,isself)

    def delname(self,_name,dparam):
        temp=self.hashdb.delname(_name)
        if temp==True:
            return (True,success,isself)
        else:
            return (False,error,isself)

    def updatename(self,_name,_newname,dparam):
        temp=self.hashdb.updatename(_name,_newname)
        if temp==True:
            return (True,success,isself)
        else:
            return (False,error,isself)

    # connects to server and check 
    def addhash(self,*args):
        if len(args)==3:
            _name,_certhash,dparam=args
            server_addr=None
        elif len(args)==4:
            server_addr,_name,_certhash,dparam=args
        else:
            return (False,("wrong amount arguments","{}".format(args)),isself)
        temp=(self.hashdb.addhash(_name,_certhash),"addhash",isself)
        
        if temp[0]==True and server_addr is not None:
            temp=self.update(server_addr,_name,_certhash)
        return temp
        
    def deljusthash(self,_certhash,dparam):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,success,isself)
        else:
            return (False,error,isself)
        
    def delhash(self,_name,_certhash,dparam):
        temp=self.hashdb.delhash(_certhash,_name)
        if temp==True:
            return (True,success,isself)
        else:
            return (False,error,isself)

    #search
    def searchhash(self,_certhash,dparam):
        temp=self.hashdb.certhash_as_name(_certhash)
        if temp is None:
            return(False, error,isself)
        else:
            return (True,temp,isself)
    
    def listhashes(self,_name,dparam):
        temp=self.hashdb.listcerts(_name)
        if temp is None:
            return(False, error,isself)
        else:
            return (True,temp,isself)
    
    def listnodenames(self,dparam):
        temp=self.hashdb.listnodenames()
        if temp is None:
            return(False, error,isself)
        else:
            return (True,temp,isself)

    def listall(self,dparam):
        temp=self.hashdb.listall()
        if temp is None:
            return (False, error,isself)
        else:
            return (True,temp,isself)

        

###server on client
    
class client_server(commonscn):
    capabilities=["basic",]
    scn_type="client"
    spmap={}
    validactions={"info","getservice","registerservice","listservices","cap","prioty","delservice"}
    def __init__(self,_name,_priority,_cert_hash,_message):
        if len(_name)==0:
            logging.debug("Name empty")
            _name="<noname>"
        
        if len(_message)==0:
            logging.debug("Message empty")
            _message="<empty>"
            
        self.name=_name
        self.message=_message
        self.priority=_priority
        self.cert_hash=_cert_hash
        
        self.update_cache()
    
    def getservice(self,_service,_addr):
        if _service not in self.spmap:
            return "{}/service".format(error)
        return "{}/{}".format(success,self.spmap[_service])
    def listservices(self,_addr):
        temp=""
        for _service in self.spmap:
            temp="{}\n{}&{}".format(temp,_service,self.spmap[_service])
        if len(temp)==0:
            return "{}/empty".format(success)
        return "{}/{}".format(success,temp[1:])
    
    def registerservice(self,_service,_port,_addr):
        if _addr[0] in ["localhost","127.0.0.1","::1"]:
            self.spmap[_service]=_port
            return "{}/registered".format(success)
        return error

    def delservice(self,_service,_addr):
        if _addr[0] in ["localhost","127.0.0.1","::1"]:
            if _service in self.spmap:
                del self.spmap[_service]
            return "{}/removed".format(success)
        return error

    def info(self,_addr):
        return self.cache["info"]

    
    def cap(self,_addr):
        return self.cache["cap"]
    
    def prioty(self,_addr):
        return self.cache["prioty"]
    
class client_handler(BaseHTTPRequestHandler):
    server_version = 'simple scn client 0.5'
    #, obsolete
    links=None
    handle_localhost=False
    handle_remote=False
    cpwhash=None
    spwhash=None
    salt=None
    statics={}
    webgui=False
        
    def html(self,page,lang="en"):
        if self.webgui==False:
            self.send_error(404,"no webgui")
            return
        _ppath="{}html{}{}{}{}".format(sharedir,os.sep,lang,os.sep,page)
        if os.path.exists(_ppath)==False:
            self.send_error(404,"file not exist")
            return
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        with open(_ppath,"rb") as rob:
            self.wfile.write(rob.read())
            #.format(name=self.links["client_server"].name,message=self.links["client_server"].message),"utf8"))
        
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
        if _cmdlist[0] not in self.links["client"].validactions:
            self.send_error(400,"invalid action - client")
            return
        _cmdlist+=[dparam,]
        if self.handle_remote==False and not self.client_address[0] in ["localhost","127.0.0.1","::1"]:
            self.send_error(401,"no permission - client")
            return
        if self.check_cpw(dparam)==False:
            self.send_error(401,"no permission - client")
            return
        
        try:
            func=type(self.links["client"]).__dict__[_cmdlist[0]]
            response=func(self.links["client"],*_cmdlist[1:])
        except AddressFail as e:
            self.send_error(500,e.msg)
            return
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st)>0:
                    self.send_error(500,st)
                else:
                    self.send_error(500,"unknown")
            return
        if response[0]==False:
            #helps against ssl failing about empty string (EOF)
            if len(response)>=1 and len(response[1])>0:
                self.send_error(400,str(response[1]))
            else:
                self.send_error(400,"unknown")
            return
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type',"text")
            self.end_headers()
            #have beginning trailing "" for indicating list
            if type(response[1]).__name__ in ["tuple","list"]:
                sumelem=""
                for listelem in response[1]:
                    if type(listelem).__name__ in ["tuple","list"]:
                        nestsum=""
                        for nestlistelem in listelem:
                            if nestlistelem is None:
                                nestsum="{}/%".format(nestsum)
                            elif nestlistelem is isself:
                                nestsum="{}/isself".format(nestsum)
                            else:
                                nestsum="{}/{}".format(nestsum,nestlistelem)
                        sumelem="{}\n{}".format(sumelem,nestsum)
                    elif listelem is isself:
                        sumelem="{}\nisself".format(sumelem)
                    elif listelem is None:
                        sumelem="{}\n%".format(sumelem)
                    else:
                        sumelem="{}\n{}".format(sumelem,listelem)
                        
                #here switch certname before content
                self.wfile.write(bytes("{}/{}".format(response[2].__str__(),sumelem),"utf8"))
            elif response[1] is None:
                self.wfile.write(bytes("{}/%".format(response[2].__str__())))
            else:
                #here switch certname before content
                self.wfile.write(bytes("{}/{}".format(response[2].__str__(),response[1]),"utf8"))

    def handle_server(self,_cmdlist):
        if _cmdlist[0] not in self.links["client_server"].validactions:
            self.send_error(400,"invalid action - server")
            return
        
         # add address to _cmdlist
        _cmdlist+=[self.client_address,]
        
        if self.check_spw()==False:
            self.send_error(401,"no permission - server")            
            return
        try:
            func=type(self.links["client_server"]).__dict__[_cmdlist[0]]
            response=func(self.links["client_server"],*_cmdlist[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st)>0:
                    self.send_error(500,st)
                else:
                    self.send_error(500,"unknown")
            else:
                self.send_error(500,"server error")
            return
        
        respparse=response.split("/",1)
        if respparse[0]==error:
            #helps against ssl failing about empty string (EOF)
            if len(respparse)>1 and len(respparse[1])>0:
                self.send_error(400,respparse[1])
            else:
                self.send_error(400,"unknown")
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type',"text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(respparse)>1 and len(respparse[1])>0:
                self.wfile.write(bytes(respparse[1],"utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))
            
    def do_GET(self):
        if self.path=="/favicon.ico":
            if "favicon.ico" in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics["favicon.ico"])
            else:
                self.send_error(404)
            return
        
        dparam={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":None}
        pos_param=self.path.find("?")
        if pos_param!=-1:
            _cmdlist=self.path[1:pos_param].split("/")
            tparam=self.path[pos_param+1:].split("&")
            for elem in tparam:
                elem=elem.split("=")

                if len(elem)==1 and elem[0]!="":
                    dparam[elem[0]]=""
                elif len(elem)==2:
                    dparam[elem[0]]=elem[1]
                else:
                    self.send_error(400,"invalid key/value pair\n{}".format(elem))
                    return
                                
        else:
            _cmdlist=self.path[1:].split("/")


        action=_cmdlist[0]

        if action=="do":
            self.handle_client(_cmdlist[1:],dparam) #remove do
            return
        elif action in self.links["client_server"].validactions:
            self.handle_server(_cmdlist)
            return

        if self.webgui==False:
            self.send_response(400,"no webgui")
            return
        #client 
        if action in ("","client","html","index"):
            self.html("client.html")
            return
        
        elif action=="static" and len(_cmdlist)>=2:
            if _cmdlist[1] in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics[_cmdlist[1]])
            else:
                self.send_response(404)
            return
        self.send_response(400,"invalid action")
     

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
    #address_family = socket.AF_INET6
    sslcont=None
    
    def __init__(self, _client_address,certfpath):
        HTTPServer.__init__(self, _client_address,client_handler)
        self.sslcont=self.sslcont=default_sslcont()
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
        #report missing file
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))
        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)

        

                
        if port is not None:
            port=int(port)
        elif len(_name)>=2:
            port=int(_name[1])
        else:
            port=0

        self.links["client_server"]=client_server(_name[0],kwargs["priority"],dhash(pub_cert),_message)
        client_handler.links=self.links
        self.links["server"]=http_client_server(("",port),_cpath+"_cert")
        self.links["client"]=client_client(_name[0],dhash(pub_cert),self.config_path+os.sep+"certdb.sqlite",self.links)

    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()

    def cmd(self):
        dparam={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":None}
        print(*self.links["client"].show(dparam)[1],sep="/")
        while True:
            inp=input("Enter command, seperate by \"/\"\nEnter parameters by closing command with \"?\" and\nadding key1=value1&key2=value2 key/value pairs:\n")
            if inp=="":
                break

            unparsed=inp.strip(" ").rstrip(" ")
            if unparsed[:5]=="hash/":
                print(dhash(unparsed[6:]))
                continue
            if unparsed[:4]=="help":
                cmdhelp()
                continue

            dparam={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":None}
            pos_param=unparsed.find("?")
            if pos_param!=-1:
                parsed=unparsed[:pos_param].split("/")
                tparam=unparsed[pos_param+1:].split("&")
                for elem in tparam:
                    elem=elem.split("=")
                    if len(elem)==1 and elem[0]!="":
                        dparam[elem[0]]=""
                    elif len(elem)==2:
                        dparam[elem[0]]=elem[1]
                    else:
                        self.send_error(400,"invalid key/value pair\n{}".format(elem))
                        return
                        
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
            except AddressFail as e:
                print("Address error")
                print(e.msg)
                
            except KeyError as e:
                print("Command does not exist?")
                print(e)
                print(parsed)
                
            except Exception as e:
                print("Error: ")
                #print(url)
                print(type(e).__name__)
                print(e)
                print(parsed)
                #print(e.printstacktrace())
    
        
cmdanot={
    "show": "general info about client",
    "register": "<serverurl>: register ip on server",
    "registerservice": "[clientname:port/]<servicename>/<serviceport>: register service on client\n    (server accepts localhost only by default)",
    "get": "<serverurl>/<name>/<hash>: retrieve ip from client from server"

    }
                
def cmdhelp():
    print(\
"""
### cmd-commands ###
""")
    for elem in client_handler.clientactions:
        if elem in cmdanot:
            print("{}:{}".format(elem,cmdanot[elem]))
        else:
            print(elem)

    print(\
"""
### cmd-parameters ###
parameters annoted with <cmd>?<parameter1>=?&<parameter2>=?
TODO
""")
    
def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
port=<number>: Port
(s/c)pwhash=<hash>: sha256 hash of pw, higher preference than pwfile
(s/c)pwfile=<file>: file with password (cleartext)
local: local reachable
remote: remote reachable
priority=<number>: set priority
timeout=<number>: #########not implemented yet ###############
webgui: enables webgui
cmd: opens cmd
s: set password for contacting client
c: set password for using client webcontrol
""")
    
def signal_handler(_signal, frame):
  sys.exit(0)

client_args={"config":default_configdir,
             "port":None,
             "cpwhash":None,
             "cpwfile":None,
             "spwhash":None,
             "spwfile":None,
             "local":None,
             "remote":None,
             "priority":"20",
             "timeout":"300", # not implemented yet
             "webgui":None,
             "cmd":None}
  
if __name__ ==  "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)

    
    if len(sys.argv)>1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem=elem.strip("-")
            if elem in ["help","h"]:
                paramhelp()
                sys.exit(0)
            else:
                tparam=elem.split("=")
                if len(tparam)==1:
                    tparam=elem.split(":")
                if len(tparam)==1:
                    client_args[tparam[0]]=""
                    continue
                client_args[tparam[0]]=tparam[1]
                

    #should be gui agnostic so specify here
    if client_args["webgui"] is not None:
        logging.debug("webgui enabled")
        client_handler.webgui=True
        #load static files
        for elem in os.listdir("{}static".format(sharedir)):
            with open("{}static{}{}".format(sharedir,os.sep,elem), 'rb') as _staticr:
                client_handler.statics[elem]=_staticr.read()
    else:
        client_handler.webgui=False

                
    cm=client_init(**client_args)
        
    if client_args["cmd"] is not None:
        logging.debug("start server")
        cm.serve_forever_nonblock()
        logging.debug("start console")
        cm.cmd()
    else:
        logging.debug("start server")
        cm.serve_forever_block()
