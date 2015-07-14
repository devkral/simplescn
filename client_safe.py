
import ssl
#import abc
from common import logger, success, error, isself, check_hash, server_port, dhash
from http import client

class client_safe(object): #abc.ABC):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "searchhash","listnames", "listnodenames", "listnodeall", "unparsedlistnames", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref"}

    hashdb = None
    links = None
    cert_hash = None
    _cache_help = None
    validactions = None
    name = None
    sslcont = None
    
    #@abc.abstractmethod
    #def do_request(self, _addr, requeststr, dheader,usecache=False,forceport=False,requesttype="GET"):
    #    pass
        
    def help(self, dheader): 
        return (True,self._cache_help,isself,self.cert_hash)
    
    #returns name,certhash,own socket
    def show(self,dheader):
        return (True,(self.name,self.cert_hash,
                str(self.links["server"].socket.getsockname()[1])),isself,self.cert_hash)
    
    def register(self,server_addr,dheader):
        return self.do_request(server_addr,"/register/{}/{}/{}".format(self.name,self.cert_hash,self.links["server"].socket.getsockname()[1]),dheader)
    
    #### indirect way to add a service ####
    def registerservice(self,_servicename,_port,dheader):
        self.links["client_server"].spmap[_servicename]=_port
        return (True,"service registered",isself,self.cert_hash)
    
    #### indirect way to delete a service ####
    def delservice(self,_servicename,dheader):
        if _servicename in self.links["client_server"].spmap:
            del self.links["client_server"].spmap[_servicename]
        return (True,"service deleted",isself,self.cert_hash)
        
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

    def cap(self,_addr,dheader):
        temp=self.do_request(_addr,  "/cap",dheader,forceport=True)
        if temp[0]==True:
            return temp[0],temp[1].split(",",3),temp[2],temp[3]
        else:
            return temp
    
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
    
    

