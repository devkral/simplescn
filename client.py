#! /usr/bin/env python3


import sys,os

sharedir=None
if sharedir is None:
    sharedir=os.path.dirname(os.path.realpath(__file__))

if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)

#import SSL as ssln
#from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import socketserver
import logging
import traceback
import ssl
import sys,signal,threading
import socket
from os import path

from common import success, error, server_port, check_certs, generate_certs, init_config_folder, default_configdir, certhash_db, default_sslcont, parse_response, dhash, VALNameError, VALHashError, isself, check_name, check_hash, dhash_salt, gen_passwd_hash, commonscn, scnparse_url, AddressFail, pluginmanager, configmanager, check_reference, check_reference_type


from common import logger


#"tdesthash": None,
#"cpwhash": None,
#"spwhash": None,
#"tpwhash":None,
reference_header = \
{
"certhash": None,
"cpwauth": None,
"spwauth": None,
"tpwauth":None,
"tdestname":None,
"tdestauth": None,
"nonce":None
}
class client_client(object):
    name=None
    cert_hash=None
    sslconts=None
    sslcontc=None
    hashdb=None
    links=None
    _cache_help = None
    pwcallmethod=input
    #isself=isself
    validactions={"register","get","connect","gethash", "help", "show","addhash", "delhash", "movehash", "get", "getlocal","listhashes","listnodenametypes", "searchhash", "addentity", "delentity", "renameentity", "listnames", "listnodenames", "listnodeall", "unparsedlistnames", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "setpriority", "delservice", "ask", "addreference","delreference","getreferences", "findbyref", "setconfig", "setpluginconfig", "access"}
    #pwcache={}
    
    def __init__(self,_name,pub_cert_hash,_certdbpath,_links):
        self._cache_help = cmdhelp()
        self.name=_name
        self.cert_hash=pub_cert_hash
        self.hashdb=certhash_db(_certdbpath)
        self.sslcont=default_sslcont()
        self.links=_links

    def do_request(self, _addr, requeststr, dheader,usecache=False,forceport=False,requesttype="GET"):
        _addr=scnparse_url(_addr,force_port=forceport)
        con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        if dhash(pcert)==self.cert_hash:
            val=isself
        elif dheader["certhash"] is not None and dheader["certhash"]!=dhash(pcert):
            raise(VALHashError)
        else:
            val=self.hashdb.certhash_as_name(dhash(pcert))
            if val=="isself":
                raise(VALNameError)

        if dheader["tdestname"] is not None and dheader["tdestauth"] is not None and dheader["nonce"] is not None:
            
            con.putrequest("CONNECT", "/{}/{}".format(dheader["tdestname"],dheader["tdestauth"]))
            pheaders={}
            if dheader["tpwauth"] is not None:
                pheaders["tpwauth"]=dheader["tpwauth"]
            #con.putheader("tdestname",dheader["tdestname"])
            #con.putheader("tdestauth",dheader["tdestauth"])

            if dheader["spwauth"] is not None:
                pheaders["spwauth"]=dheader["spwauth"]
            if dheader["cpwauth"] is not None:
                con.putheader("cpwauth",dheader["cpwauth"])
            if dheader["nonce"] is not None:
                con.putheader("nonce",dheader["nonce"])
            con.set_tunnel(requeststr,pheaders)
        else:
            con.putrequest(requesttype, requeststr)
            
            if dheader["spwauth"] is not None:
                con.putheader("spwauth",dheader["spwauth"])
            if dheader["cpwauth"] is not None:
                con.putheader("cpwauth",dheader["cpwauth"])
            if dheader["nonce"] is not None:
                con.putheader("nonce",dheader["nonce"])
        if usecache==False:
            con.putheader("Cache-Control", "no-cache")
        
        con.endheaders()
        r=con.getresponse()
        if r.status in [401,406,407]:
            if r.status in [401,]:
                dheader["spwauth"]=dhash_salt(dhash(self.pwcallmethod("Please enter password for server")),os.urandom(10))#r.read())
            if r.status in [406,]:
                dheader["cpwauth"]=dhash_salt(dhash(self.pwcallmethod("Please enter password for client")),os.urandom(10))
            if r.status in [407,]:
                dheader["tpwauth"]=dhash_salt(dhash(self.pwcallmethod("Please enter password for proxy")),os.urandom(10))
            return self.do_request(_addr, requeststr, dheader, usecache, forceport, requesttype)
        else:
            resp=parse_response(r)
            con.close()
            if len(resp)>=2:
                return resp[0],resp[1],val,dhash(pcert)
            else:
                return False, "invalid amount of return values:\n" ,val,dhash(pcert)
    
    def help(self, dheader): 
        return (True,self._cache_help,isself,self.cert_hash)
        
    def show(self,dheader):
        return (True,(self.name,self.cert_hash,
                str(self.links["server"].socket.getsockname()[1])),isself,self.cert_hash)
    
    def register(self,server_addr,dheader):
        return self.do_request(server_addr,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.links["server"].socket.getsockname()[1]),dheader)
    
    def get(self, server_addr, _name, _hash, dheader):
        temp=self.do_request(server_addr,"/get/{}/{}".format(_name,_hash),dheader)
        if temp[0]==False:
            return temp
        if temp[1].find(":") == -1:
            return (False,"splitting not possible",temp[1])
        address,port=temp[1].rsplit(":",1)
            
        try:
            temp2=(temp[0],(address,int(port)),temp[2],temp[3])
        except ValueError:
            return (False,"port not a number:\n{}".format(temp[1]))
        if temp2[1][1]<1:
            return (False,"port <1:\n{}".format(temp[1][1]))
        return temp2
        
    
    def gethash(self,_addr,dheader):
        _addr=_addr.split(":")
        if len(_addr)==1:
            _addr=(_addr[0],server_port)
        try:
            con=client.HTTPSConnection(_addr[0],_addr[1],context=self.sslcont)
            con.connect()
            pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            con.close()
            return (True,(dhash(pcert),pcert),isself,self.cert_hash)
        except ssl.SSLError:
            return (False,"server speaks no tls 1.2")
        except Exception:
            return (False,"server does not exist")

    def ask(self,_address,dheader):
        _ha=self.gethash(_address,dheader)
        if _ha[0]==False:
            return _ha
        if _ha[1][0]==self.cert_hash:
            return (True,(isself,self.cert_hash),isself,self.cert_hash)
        temp=self.hashdb.certhash_as_name(_ha[1][0])
        return (True,(temp,_ha[1][0]),isself,self.cert_hash)

    def unparsedlistnames(self,server_addr,dheader):
        return self.do_request(server_addr, "/listnames",dheader,usecache=True)

    def listnames(self,server_addr,dheader):
        temp=self.unparsedlistnames(server_addr,dheader)
        if temp[0]==False:
            return temp
        temp2=[]
        if temp[1]!="empty":
            for line in temp[1].split("\n"):
                _split=line.split("/")
                if len(_split)!=2:
                    logger().debug("invalid element:\n{}".format(line))
                    continue
                if _split[0]=="isself":
                    logger().debug("invalid name:\n{}".format(line))
                    continue
                if _split[1]==self.cert_hash:
                    temp2+=[(_split[0],_split[1],isself),] 
                else:
                    temp2+=[(_split[0],_split[1],self.hashdb.certhash_as_name(_split[1])),]
        return (temp[0],temp2,temp[2],temp[3])
    
    def getservice(self,client_addr,_service,dheader):
        return self.do_request(client_addr, "/getservice/{}".format(_service),dheader)

    #### second way to add or remove a service
    def registerservice(self,_servicename,_port,dheader):
        self.links["client_server"].spmap[_servicename]=_port
        return (True,"service registered",isself,self.cert_hash)

    def delservice(self,_servicename,dheader):
        if _servicename in self.links["client_server"].spmap:
            del self.links["client_server"].spmap[_servicename]
        return (True,"service deleted",isself,self.cert_hash)
        
    def listservices(self,*args):
        if len(args)==1:
            dheader=args[0]
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            client_addr,dheader=args
        else:
            return (False,("wrong amount arguments (listservices): {}".format(args)))
        temp=self.do_request(client_addr, "/listservices",dheader,forceport=True)
        if temp[0]==False:
            return temp
        temp2=[]
        if temp[1]!="empty":
            for elem in temp[1].split("\n"):
                temp2+=[elem.rsplit("&",1),]
        return (temp[0],temp2,temp[2],temp[3])
    
    def info(self,*args):
        if len(args)==1:
            dheader=args[0]
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            _addr,dheader=args
        else:
            return (False,("wrong amount arguments (info): {}".format(args)))
        _tinfo=self.do_request(_addr, "/info", dheader, forceport=True)
        if _tinfo[0]==True:
            _tinfolist=_tinfo[1].split("/",2)
            return (True,_tinfolist,_tinfo[2],_tinfo[3])
            
        else:
            return _tinfo

    def prioty_direct(self,*args):
        if len(args)==1:
            dheader=args[0]
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        elif len(args)==2:
            _addr,dheader=args
        else:
            return (False,("wrong amount arguments (priority_direct): {}".format(args)),isself)
        temp=self.do_request(_addr,  "/prioty",dheader,forceport=True)
        return temp

    def prioty(self,server_addr,_name,_hash,dheader):
        temp=self.get(server_addr,_name,_hash,dheader)
        if temp[0]==False:
            return temp
        return self.prioty_direct(temp[1])

    def setpriority(self,*args):
        if len(args)==2:
            _priority,dheader=args
        else:
            return (False,("wrong amount arguments (setpriority): {}".format(args)))
        if type(_priority).__name__=="str" and _priority.isdecimal()==False:
            return (False,"no integer")
        elif type(_priority).__name__=="str":
            _priority=int(_priority)
        elif type(_priority).__name__!="int":
            return (False,"unsupported datatype")
        if _priority<0 or _priority>100:
            return (False,"out of range")
        
        self.links["server"].priority=_priority
        self.links["server"].update_prioty()
        return (True,"priority",isself,self.cert_hash)

    def capabilities(self,_addr,dheader):
        temp=self.do_request(_addr,  "/cap",dheader,forceport=True)
        if temp[0]==True:
            return temp[0],temp[1].split(",",3),temp[2],temp[3]
        else:
            return temp

    #check if _addr is reachable and update priority
    def check_direct(self,_addr,_namelocal,_hash,dheader):
        dheader["certhash"]=_hash #ensure this
        
        temp=self.prioty_direct(_addr,dheader)
        if temp[0]==False:
            return temp
        
        if self.hashdb.exist(_namelocal,_hash)==True:
            self.hashdb.changepriority(_namelocal,_hash,temp[1][0])
            self.hashdb.changetype(_namelocal,_hash,temp[1][1])
        return temp
    
    #check if node is reachable and update priority
    def check(self,server_addr,_name,_namelocal,_hash,dheader):
        temp=self.get(server_addr,_name,_hash,dheader)
        if temp[0]==False:
            return temp
        return self.check_direct(temp[1],_namelocal,_hash,dheader)
    
    #local management
    def addentity(self,_name,dheader):
        temp=self.hashdb.addentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def delentity(self,_name,dheader):
        temp=self.hashdb.delentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def renameentity(self,_name,_newname,dheader):
        temp=self.hashdb.renameentity(_name,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def addhash(self,*args):
        if len(args)==3:
            _name, _certhash, dheader=args
            _type=None
        elif len(args)==4:
            _name, _certhash, _type, dheader=args
        else:
            return (False,("wrong amount arguments (addhash): {}".format(args)))
        if self.hashdb.addhash(_name,_certhash,_type) == False:
            return (False,"addhash failed")
        else:
            return (True, success, isself, self.cert_hash)

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success,isself,self.cert_hash)
    #    else:
    #        return (False,error)
        
    def delhash(self,_certhash,dheader):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)
            
    def movehash(self,_certhash,_newname,dheader):
        temp=self.hashdb.movehash(_certhash,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    #search
    def searchhash(self,_certhash,dheader):
        temp=self.hashdb.certhash_as_name(_certhash)
        if temp is None:
            return(False, error)
        else:
            return (True,temp,isself,self.cert_hash)
            
    def getlocal(self,_name,_certhash,_dheader):
        temp=self.hashdb.get(_name,_certhash)
        if temp is None:
            return(False, error)
        else:
            return (True,temp,isself,self.cert_hash)
    
    def listhashes(self, *args):
        if len(args) == 3:
            _name, _nodetypefilter, dheader = args
        elif len(args) == 2:
            _name, dheader=args
            _nodetypefilter = None
        else:
            return (False,("wrong amount arguments (listhashes): {}".format(args)))
        temp=self.hashdb.listhashes(_name,_nodetypefilter)
        if temp is None:
            return(False, error)
        else:
            return (True,temp,isself,self.cert_hash)
    
    def listnodenametypes(self,dheader):
        temp=self.hashdb.listnodenametypes()
        if temp is None:
            return(False, error)
        else:
            return (True,temp,isself,self.cert_hash)
    
    def listnodenames(self,*args):
        if len(args)==2:
            _nodetypefilter,dheader=args
        elif len(args)==1:
            dheader=args[0]
            _nodetypefilter=None
        else:
            return (False,("wrong amount arguments (listnodenames): {}".format(args)))
        temp=self.hashdb.listnodenames(_nodetypefilter)
        if temp is None:
            return(False, error)
        else:
            return (True,temp,isself,self.cert_hash)

    def listnodeall(self, *args):
        if len(args)==2:
            _nodetypefilter,dheader=args
        elif len(args)==1:
            dheader=args[0]
            _nodetypefilter=None
        else:
            return (False,("wrong amount arguments (listnodeall): {}".format(args)))
        temp=self.hashdb.listnodeall(_nodetypefilter)
        if temp is None:
            return (False, error)
        else:
            return (True,temp,isself,self.cert_hash)
    
    def addreference(self,*args):
        if len(args)==5:
            _name,_certhash,_reference,_reftype,dheader=args
        elif len(args)==4:
            _certhash,_reference,_reftype,dheader=args
            _name=self.hashdb.certhash_as_name(_certhash)
            if _name is None:
                return (False,"name not in db")
        else:
            return (False,("wrong amount arguments (addreference): {}".format(args)))
        
        if check_reference(_reference)==False:
            return (False,"reference invalid")
        if check_reference_type(_reftype)==False:
            return (False,"reference type invalid")
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist")
        if self.hashdb.addreference(_tref[2],_reference,_reftype) is None:
            return (False,"adding a reference failed")
        return (True,_reftype,isself,self.cert_hash)
        
    def delreference(self,*args):
        if len(args)==4:
            _name,_certhash,_reference,dheader=args
        elif len(args)==3:
            _certhash,_reference,dheader=args
            _name=self.hashdb.certhash_as_name(_certhash)
            if _name is None:
                return (False,"name not in db")
        else:
            return (False,("wrong amount arguments (delreference): {}".format(args)))
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist")
        if self.hashdb.delreference(_tref[2],_reference) is None:
            return (False,error)
        return (True,success,isself,self.cert_hash)
        
    def getreferences(self,*args):
        if len(args) == 3:
            _certhash,_reftypefilter,dheader=args
        elif len(args) == 2:
            _certhash,dheader=args
            _reftypefilter=None
        else:
            return (False,("wrong amount arguments (getreferences): {}".format(args)))
        if check_hash(_certhash)==True:
            _localname=self.hashdb.certhash_as_name(_certhash) #can return None to sort out invalid hashes
        else:
            _localname=None
        if _localname is None:
            return (False, "certhash does not exist: {}".format(_certhash))
        _tref=self.hashdb.get(_localname, _certhash)
        if _tref is None:
            return (False,"error in hashdb")
        temp=self.hashdb.getreferences(_tref[2], _reftypefilter)
        if temp is None:
            return (False,error)
        return (True,temp,isself,self.cert_hash)
        
    def findbyref(self,_reference,dheader):
        temp=self.hashdb.findbyref(_reference)
        if temp is None:
            return (False,error)
        return (True,temp,isself,self.cert_hash)
    
    def setconfig(self, _key, _value,dheader):
        ret = self.links["configmanager"].set(_key, _value)
        if ret == True:
            return (True, success,isself,self.cert_hash)
        else:
            return (False, error)
    
    def setpluginconfig(self, _plugin, _key, _value, dheader):
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if _plugin not in listplugin:
            return (False, "plugin does not exist")
        if _plugin not in pluginm.plugins:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins",_plugin))
        else:
            config = pluginm.plugins.config
        config.set(_key, _value)
        return (True,success,isself,self.cert_hash)
    
    
    # command wrapper for cmd interfaces
    def command(self,inp):
        reqheader=reference_header.copy()
        ret = [False, None, self.cert_hash, isself ]
        if inp == "":
            #ret[output] =
            return ret
        unparsed=inp.strip(" ").rstrip(" ")
        if unparsed[:5]=="hash/":
            ret[0] = True
            ret[1] = "Hash: {}".format(dhash(unparsed[6:]))
            return ret
        
        pos_header=unparsed.find("?")
        if pos_header!=-1:
            parsed=unparsed[:pos_header].split("/")
            tparam=unparsed[pos_header+1:].split("&")
            for elem in tparam:
                elem=elem.split("=")
                if len(elem)==1 and elem[0]!="":
                    reqheader[elem[0]]=""
                elif len(elem)==2:
                    reqheader[elem[0]]=elem[1]
                else:
                    ret[0] = False
                    ret[1] = "Error: invalid key/value pair\n{}".format(elem)
                    return ret
        else:
            parsed=unparsed.split("/")
        
        #call functions in plugins
        if str(parsed[0]) == "plugin":
            plugins=self.links["client_server"].pluginmanager.plugins
            if plugins is None:
                return
            if parsed[1] not in plugins:
                ret[0] = False
                ret[1] = "Error: plugin does not exist"
                return ret
            plugin = plugins[parsed[1]]
            if "cmd_node_actions" not in plugin.__dict__:
                ret[0] = False
                ret[1] = "Error: plugin does not support commandline"
                return ret
                
            action = str(parsed[2])
            if "cmd_node_localized_actions" in plugin.__dict__ and \
                    action in plugin.cmd_node_localized_actions:
                    action = plugin.cmd_node_localized_actions[action]
            try:
                
                resp = plugin.cmd_node_actions[action][0](*parsed[2:])
                ret[0] = True
                ret[1] = str(resp)
            except Exception as e:
                st="Error: {}\n".format(e)
                if "tb_frame" in e.__dict__:
                    st="{}\n{}\n\n".format(st,traceback.format_tb(e))
                st = "{}Errortype: {}\nCommandline: {}".format(st, type(e).__name__, parsed)
                ret[0] = False
                ret[1] = "Error:\n{}".format(st)
            return ret
        
        # call functions in client
        parsed+=[reqheader,]
        
        if str(parsed[0]) not in self.validactions:
            ret[0] = False
            ret[1] = "Error: Command does not exist/is not public: {}".format(parsed[0])
            return ret
        try:
            func=type(self).__dict__[str(parsed[0])]
            resp=func(self,*parsed[1:])
            ret[0] = resp[0]
            ret[1] = str(resp[1])
            if resp[0] == True:
                ret[2] = resp[2]
                ret[3] = resp[3]
        except AddressFail as e:
            ret[0] = False
            ret[1] = "Addresserror:\n{}".format(e.msg)
        except Exception as e:
            st="Error: {}\n".format(e)
            if "tb_frame" in e.__dict__:
                st="{}\n{}\n\n".format(st,traceback.format_tb(e))
            st = "{}Errortype:{}\nCommandline: {}".format(st, type(e).__name__, parsed)
            ret[0] = False
            ret[1] = "Error:\n{}".format(st)
        return ret
    
    # for e.g. plugins
    def access(self, func, *args, dheader=reference_header.copy()):
        if func in self.validactions and func != "access":
            args.append(dheader)
            return client_client.__dict__[func](self, *args)


###server on client
    
class client_server(commonscn):
    capabilities = ["basic",]
    scn_type = "client"
    spmap = {}
    validactions = {"info", "getservice", "listservices", "cap", "prioty", "registerservice", "delservice"}
    local_client_service_control = False
    wlock = None
    def __init__(self, _name, _priority, _cert_hash, _message):
        self.wlock = threading.Lock()
        if len(_name) == 0:
            logger().debug("Name empty")
            _name = "<noname>"

        if len(_message) == 0:
            logger().debug("Message empty")
            _message = "<empty>"
            
        self.name = _name
        self.message = _message
        self.priority = _priority
        self.cert_hash = _cert_hash
        
        self.update_cache()
    ### the primary way to add or remove a service
    ### can be called by every application on same client, maybe add additional protection
    def registerservice(self, _service, _port, _addr):
        if _addr[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            self.spmap[_service] = _port
            self.wlock.release()
            return "{}/registered".format(success)
        return error

    def delservice(self, _service, _addr):
        if _addr[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            if _service in self.spmap:
                del self.spmap[_service]
            self.wlock.release()
            return "{}/removed".format(success)
        return error
        
    ### management section - end ###
    
    def getservice(self, _service, _addr):
        if _service not in self.spmap:
            return "{}/service".format(error)
        return "{}/{}".format(success, self.spmap[_service])

    def listservices(self, _addr):
        temp = ""
        for _service in self.spmap:
            temp = "{}\n{}&{}".format(temp, _service, self.spmap[_service])
        if len(temp) == 0:
            return "{}/empty".format(success)
        return "{}/{}".format(success, temp[1:])

    def info(self, _addr):
        return self.cache["info"]

    def cap(self, _addr):
        return self.cache["cap"]
    
    def prioty(self, _addr):
        return self.cache["prioty"]
    
class client_handler(BaseHTTPRequestHandler):
    server_version = 'simple scn client 0.5'

    links = None
    handle_localhost = False
    handle_remote = False
    cpwauth = None
    spwhash = None
    statics = {}
    webgui = False
        
    def html(self, page, lang = "en"):
        if self.webgui == False:
            self.send_error(404, "no webgui")
            return
        _ppath = os.path.join(sharedir, "html", lang, page)
        if os.path.exists(_ppath) == False:
            self.send_error(404, "file not exist")
            return
        self.send_response(200)
        self.send_header('Content-type', "text/html")
        self.end_headers()
        with open(_ppath, "rb") as rob:
            self.wfile.write(rob.read())
            #.format(name=self.links["client_server"].name,message=self.links["client_server"].message),"utf8"))

    def check_cpw(self):
        if self.cpwhash is None:
            return True
        if "cpwauth" in self.headers and "nonce" in self.headers:
            if dhash_salt(self.headers["cpwauth"], self.headers["nonce"]) == self.cpwhash:
                return True
        return False

    def check_spw(self):
        if self.spwhash is None:
            return True
        if "spwhash" in self.headers and "nonce" in self.headers:
            if dhash_salt(self.headers["spwhash"],self.headers["nonce"]) == self.spwhash:
                return True
        
        return False
    
    def handle_client(self, _cmdlist):
        if _cmdlist[0] not in self.links["client"].validactions:
            self.send_error(400, "invalid action - client")
            return
        _cmdlist += [self.headers,]
        if self.handle_remote == False and not self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
            self.send_error(403, "no permission - client")
            return
        if self.check_cpw() == False:
            self.send_error(406, "client - auth fail") #"no permission - client")
            return
        
        try:
            func = type(self.links["client"]).__dict__[_cmdlist[0]]
            response = func(self.links["client"], *_cmdlist[1:])
        except AddressFail as e:
            self.send_error(500, e.msg)
            return
        except Exception as e:
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st) > 0:
                    self.send_error(500, st)
                else:
                    self.send_error(500, "unknown")
            return
        if response[0] == False:
            #helps against ssl failing about empty string (EOF)
            if len(response) >= 1 and len(response[1]) > 0:
                self.send_error(400, str(response[1]))
            else:
                self.send_error(400, "unknown")
            return
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type', "text")
            self.end_headers()
            #have beginning trailing "" for indicating list
            if type(response[1]).__name__ in ["tuple", "list"]:
                sumelem = ""
                for listelem in response[1]:
                    if type(listelem).__name__ in ["tuple", "list"]:
                        nestsum = ""
                        for nestlistelem in listelem:
                            if nestlistelem is None:
                                nestsum = "{}/%".format(nestsum)
                            elif nestlistelem is isself:
                                nestsum = "{}/isself".format(nestsum)
                            else:
                                nestsum = "{}/{}".format(nestsum, nestlistelem)
                        sumelem = "{}\n{}".format(sumelem, nestsum)
                    elif listelem is isself:
                        sumelem = "{}\nisself".format(sumelem)
                    elif listelem is None:
                        sumelem = "{}\n%".format(sumelem)
                    else:
                        sumelem = "{}\n{}".format(sumelem, listelem)

                #here switch certname before content
                self.wfile.write(bytes("{}/{}".format(response[2].__str__(), sumelem), "utf8"))
            elif response[1] is None:
                self.wfile.write(bytes("{}/%".format(response[2].__str__())))
            else:
                #here switch certname before content
                self.wfile.write(bytes("{}/{}".format(response[2].__str__(), response[1]), "utf8"))

    def handle_server(self, _cmdlist):
        if _cmdlist[0] not in self.links["client_server"].validactions:
            self.send_error(400, "invalid action - server")
            return
        
         # add address to _cmdlist
        _cmdlist += [self.client_address,]
        
        if self.check_spw() == False:
            self.send_error(401, "client-server auth-fail")
            return
        try:
            func = type(self.links["client_server"]).__dict__[_cmdlist[0]]
            response = func(self.links["client_server"], *_cmdlist[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                if "tb_frame" in e.__dict__:
                    st = str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st = str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st) > 0:
                    self.send_error(500, st)
                else:
                    self.send_error(500, "unknown")
            else:
                self.send_error(500, "server error")
            return
        
        respparse = response.split("/", 1)
        if respparse[0] == error:
            #helps against ssl failing about empty string (EOF)
            if len(respparse) > 1 and len(respparse[1]) > 0:
                self.send_error(400, respparse[1])
            else:
                self.send_error(400, "unknown")
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type', "text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(respparse) > 1 and len(respparse[1]) > 0:
                self.wfile.write(bytes(respparse[1], "utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))
            
    def do_GET(self):
        if self.path == "/favicon.ico":
            if "favicon.ico" in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics["favicon.ico"])
            else:
                self.send_error(404)
            return
        
        pos_header = self.path.find("?")
        if pos_header != -1:
            _cmdlist = self.path[1:pos_header].split("/")
            tparam = self.path[pos_header+1:].split("&")
            for elem in tparam:
                elem = elem.split("=")

                if len(elem) == 2:
                    self.headers[elem[0]] = elem[1]
                else:
                    self.send_error(400, "invalid key/value pair\n{}".format(elem))
                    return
        else:
            _cmdlist = self.path[1:].split("/")

        action = _cmdlist[0]

        if action == "do":
            self.handle_client(_cmdlist[1:]) #remove do
            return
        elif action in self.links["client_server"].validactions:
            self.handle_server(_cmdlist)
            return
        if self.webgui == False:
            self.send_error(400, "no webgui")
            return
        #client 
        if action in ("", "client", "html", "index"):
            self.html("client.html")
            return
        elif action == "static" and len(_cmdlist) >= 2:
            if _cmdlist[1] in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics[_cmdlist[1]])
            else:
                self.send_error(404, "invalid static object")
            return
        
        self.send_error(400, "invalid action")
    
    def do_PUT(self):
        reqheader=reference_header.copy()
        pos_header = self.path.find("?")
        if pos_header != -1:
            _cmdlist = self.path[1:pos_header].split("/")
            tparam = self.path[pos_header+1:].split("&")
            for elem in tparam:
                elem = elem.split("=")

                if len(elem) == 1 and elem[0] != "":
                    reqheader[elem[0]] = ""
                elif len(elem) == 2:
                    reqheader[elem[0]] = elem[1]
                else:
                    self.send_error(400,"invalid key/value pair\n{}".format(elem))
                    return
        else:
            _cmdlist = self.path[1:].split("/")

        action = _cmdlist[0]
        if action == "do":
            self.handle_client(_cmdlist[1:], reqheader) #removes do


    def do_POST(self):
        plugin, action=self.path[1:].split("/",1)
        pluginm = self.links["client_server"].pluginmanager
        if pluginm is None:
            return
        if pluginm.redirect_addr in ["",None]:
            if "receive" in pluginm.plugins[plugin].__dict__:
                try:
                    pluginm.plugins[plugin].receive(action, self.rfile, self.wfile)
                except Exception as e:
                    logger().error(e)
                    return
        else:
            self.links["client_client"].do_request(pluginm.redirect_addr, \
                                            self.path, requesttype = "POST")
            return
        
        
class http_client_server(socketserver.ThreadingMixIn,HTTPServer):
    """server part of client; inheritates client_server to provide
        client information"""
    #address_family = socket.AF_INET6
    sslcont = None
    
    
    def __init__(self, _client_address, certfpath):
        HTTPServer.__init__(self, _client_address, client_handler)
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv")
        self.socket = self.sslcont.wrap_socket(self.socket)
        


class client_init(object):
    config_root=None
    plugins_config=None
    links={}
    
    def __init__(self,confm,pluginm):
        self.links["config"]=confm
        self.links["config_root"]=confm.get("config")
        
        _cpath=os.path.join(self.links["config_root"],"client")
        init_config_folder(self.links["config_root"],"client")
        
        if confm.getb("webgui")!=False:
            logger().debug("webgui enabled")
            client_handler.webgui=True
            #load static files
            for elem in os.listdir(os.path.join(sharedir, "static")):
                with open(os.path.join(sharedir,"static",elem), 'rb') as _staticr:
                    client_handler.statics[elem]=_staticr.read()
        else:
            client_handler.webgui=False
        
        client_handler.salt = os.urandom(8)
        if confm.getb("local") == True:
            client_handler.handle_localhost=True
        elif confm.getb("cpwhash") == True:
            if confm.getb("remote") == True:
                client_handler.handle_remote = True
            client_handler.handle_localhost = True
            client_handler.cpwhash=confm.get("cpwhash")
        elif confm.getb("cpwfile") == True:
            if confm.getb("remote") == True:
                client_handler.handle_remote=True
            client_handler.handle_localhost=True
            op=open("r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            client_handler.cpwhash=dhash(pw)
            op.close()
            
        if confm.getb("spwhash") == True:
            client_handler.spwhash = confm.get("spwhash")
        elif confm.getb("spwfile") == True:
            op=open("r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            client_handler.spwhash = dhash(pw)
            op.close()
        
        if check_certs(_cpath+"_cert") == False:
            logger().debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logger().debug("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read()

        with open(_cpath+"_name", 'r') as readclient:
            _name = readclient.readline()
        with open(_cpath+"_message", 'r') as readinmes:
            _message = readinmes.read()
            if _message[-1] in "\n":
                _message = _message[:-1]
        #report missing file
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))
        
        _name = _name.split("/")
        if len(_name)>2 or check_name(_name[0]) == False:
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)

        if confm.getb("port") == True:
            port = int(port)
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = 0

        self.links["client_server"] = client_server(_name[0], confm.get("priority"), dhash(pub_cert), _message)
        self.links["configmanager"] = confm

        client_handler.links=self.links
        self.links["server"]=http_client_server(("",port),_cpath+"_cert")
        self.links["client"]=client_client(_name[0],dhash(pub_cert),os.path.join(self.links["config_root"], "certdb.sqlite"),self.links)
        self.links["client_server"].pluginmanager=pluginm
        
        
    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()
        
cmdanot={
    "help": ("", "open help"),
    "show": ("","general info about client"),
    "setconfig": (" <key>/<value>", "set key of main config to value"),
    "setpluginconfig": (" <plugin>/<key>/<value>", "set key of plugin config to value"),
    "register": (" <serverurl>", "register ip on server"),
    "registerservice": (" [clientname:port/]<servicename>/<serviceport>", "register service on client\n    (server accepts only localhost by default)"),
    "get": (" <serverurl>/<name>/<hash>", "retrieve ip from client from server")

    }
                
def cmdhelp():
    out="""### cmd-commands ###
hash <pw>: calculate hash for pw
plugin <plugin>/<...>: speak with plugin
"""
    for elem in client_client.validactions:
        if elem in cmdanot:
            out+="{}{}: {}".format(elem,*cmdanot[elem])+"\n"
        else:
            out+="{}: {}".format(elem,"<undocumented>")+"\n"

    out+="""
### cmd-headers ###
headers defined this way: ...?<header1>=<value1>&<header2>=<value2>...
TODO
"""
    return out
    
def paramhelp():
    return """
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
"""
    
def signal_handler(_signal, frame):
  sys.exit(0)


#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args={"noplugins":None,
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
             
client_args={"config":default_configdir,
             "port":None}

if __name__ ==  "__main__":    
    from common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    
    pluginpathes=[os.path.join(sharedir, "plugins")]
    
    if len(sys.argv) > 1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help","h"]:
                print(paramhelp())
                sys.exit(0)
            else:
                tparam=elem.split("=")
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    client_args[tparam[0]] = "True"
                    continue
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1], ]
                    continue
                client_args[tparam[0]] = tparam[1]

    configpath=client_args["config"]
    configpath=path.expanduser(configpath)
    if configpath[-1]==os.sep:
        configpath=configpath[:-1]
    client_args["config"]=configpath
    # path  to plugins in config folder
    pluginpathes.insert(1,os.path.join(configpath, "plugins"))
    
    # path to config folder of plugins
    configpath_plugins=os.path.join(configpath, "config", "plugins")
    #if configpath[:-1]==os.sep:
    #    configpath=configpath[:-1]
    
    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    confm = configmanager(os.path.join(configpath, "config", "clientmain.conf"))
    confm.update(default_client_args,client_args)

    if confm.getb("noplugins")==False:
        pluginm=pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui")!=False:
            pluginm.interfaces+=["web",]
        if confm.getb("cmd")!=False:
            pluginm.interfaces+=["cmd",]
    else:
        pluginm=None

    cm=client_init(confm,pluginm)

    if confm.getb("noplugins")==False:
        # needs nothing as resources as spoken via post
        # pluginm.resources["links"] = cm.links
        # function
        #pluginm.resources["client"] = cm.links["client"].request_plugins()
        pluginm.init_plugins()

    if confm.getb("cmd")!=False:
        logger().debug("start client server")
        cm.serve_forever_nonblock()
        logger().debug("start console")
        print(*cm.links["client"].show({})[1],sep="/")
        while True:
            ret=cm.links["client"].command(input("Enter command, seperate by \"/\"\nEnter headers by closing command with \"?\" and\nadding key1=value1&key2=value2 key/value pairs:\n"))
            if ret[0] == True:
                if ret[2] is isself:
                    print("This client:")
                else:
                    print("{} with hash:\n{}\n answers:".format(ret["certname"],ret["hash"]))
            print(ret[1])
        #cm.cmd_cmd()
    else:
        logger().debug("start client server")
        cm.serve_forever_block()
