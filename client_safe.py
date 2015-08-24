
import ssl
#import abc
from common import logger, success, error, isself, check_hash, server_port, dhash
from http import client
import json

class client_safe(object): #abc.ABC):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "searchhash","listnames", "listnodenames", "listnodeall", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref"}

    hashdb = None
    links = None
    cert_hash = None
    _cache_help = None
    validactions = None
    name = None
    sslcont = None
    
    
    def help(self, obdict): 
        return True, self._cache_help
    
    def register(self, obdict):
        if check_args(obdict, (("server",str),)) == False:
            return False, "check_args failed (register)"
        return self.do_request(obdict("server"),"/server/register", {"name":self.name, "certhash": self.cert_hash, "port": self.show()[1]["port"]}, obdict["header"])
    
    #returns name,certhash,own socket
    def show(self, obdict):
        return True,{"name": self.name, "certhash": self.cert_hash,
                "port":str(self.links["server"].socket.getsockname()[1])}
    
    #### second way to add a service ####
    def registerservice(self, obdict):
        if check_args(obdict, (("service",str),("port",int))) == False:
            return False, "check_args failed (registerservice)"
        self.links["client_server"].spmap[obdict["service"]] = obdict["port"]
        return True,"service registered"
    
    #### second way to delete a service ####
    def delservice(self, obdict):
        if check_args(obdict, (("service",str),)) == False:
            return False, "check_args failed (delservice)"
        if obdict["service"] in self.links["client_server"].spmap:
            del self.links["client_server"].spmap[obdict["service"]]
        return True,"service deleted"
    
    # check
    def get(self,obdict):
        if check_args(obdict, (("server",str),("name",str),("certhash",str))) == False:
            return False, "check_args failed (get)"
        temp = self.do_request(obdict["server"],"/server/get", obdict,obdict["headers"])
        if temp[0] == False:
            return temp
        try:
            address, port = temp[1]
        except Exception as e:
            return False, "splitting failed: {}".format(e)
        try:
            temp2=(temp[0],{"address": address,"port": int(port)},temp[2],temp[3])
        except ValueError:
            return False,"port not a number:\n{}".format(temp[1])
        if temp2[1][1]<1:
            return False,"port <1:\n{}".format(temp[1][1])
        return temp2
        
    
    def gethash(self, obdict):
        if check_args(obdict, (("address",str),)) == False:
            return False, "check_args failed (gethash)"
        try:
            con = client.HTTPSConnection(obdict["address"], context=self.sslcont)
            con.connect()
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            con.close()
            return True, {"certhash":dhash(pcert), "cert":pcert}
        except ssl.SSLError:
            return False, "server speaks no tls 1.2"
        except ConnectionRefusedError:
            return False, "server does not exist"
        except Exception as e:
            return False, "Other error: {}".format(e)

    def ask(self, obdict): #_address):
        if check_args(obdict, (("address",str),)) == False:
            return False, "check_args failed (ask)"
        _ha = self.gethash(_address)
        if _ha[0] == False:
            return _ha
        if _ha[1]["certhash"] == self.cert_hash:
            return True, {"certname":isself, "certhash":self.cert_hash}
        temp = self.hashdb.certhash_as_name(_ha[1]["certhash"])
        return True, {"certname":temp, "certhash":_ha[1]["certhash"]}

    def listnames(self, obdict):
        if check_args(obdict, (("server",str),)) == False:
            return False, "check_args failed (ask)"
        temp = self.do_request(obdict["server"], "/server/listnames", headers=obdict["headers"])
        if temp[0] == False:
            return temp
        out = []
        try:
            temp2 = json.loads(temp[1])
            for name in sorted(temp2):
                if name == isself:
                    logging.debug("Scamming attempt: SKIP")
                    continue
                    
                for _hash in sorted(temp2[name]):
                    if _hash == self.cert_hash:
                        out.append((name, _hash, isself))
                    else:
                        certname = self.hashdb.certhash_as_name(_hash)
                        out.append((name, _hash, certname))
                        
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, e)
        return True, out
    
    def getservice(self, obdict):
        if check_args(obdict, (("address",str),("service",str))) == False:
            client_addr=obdict["address"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice",obdict,headers=obdict["headers"])
    
    def listservices(self, obdict):
        if check_args(obdict, (("address",str),)) == False:
            client_addr=obdict["address"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        temp=self.do_request(client_addr, "/server/listservices",headers=obdict["headers"],forceport=True)
        if temp[0]==False:
            return temp
        temp2={}
        try:
            temp2 = json.loads(temp[1])
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, e)
        temp3=[]
        for elem in sorted(temp2.keys()):
            temp3.append((elem,temp2[elem]))
        return temp[0],temp3,temp[2],temp[3]
    
    def info(self, obdict):
        if check_args(obdict, (("address",str),)) == False:
            client_addr=obdict["address"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        
        _tinfo=self.do_request(_addr, "/server/info", headers=obdict["headers"], forceport=True)
        if _tinfo[0]==False:
            return _tinfo
        temp2={}
        try:
            temp2 = json.loads(_tinfo[1])
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, e)
        return True, temp2, _tinfo[2], _tinfo[3]

    def cap(self, obdict):
        if check_args(obdict, (("address",str),)) == False:
            client_addr=obdict["address"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        
        temp = self.do_request(_addr, "/server/cap", headers=obdict["headers"], forceport=True)
        if temp[0] == False:
            return temp
        
        temp2 = {}
        try:
            temp2 = json.loads(_tinfo[1])
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, e),isself,self.cert_hash
        return True, temp2, temp[2], temp[3]
        
    def prioty_direct(self, obdict):
        if check_args(obdict, (("address",str),)) == False:
            client_addr = obdict["address"]
        else:
            client_addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        
        _tprioty = self.do_request(_addr,  "/server/prioty",headers=obdict["headers"],forceport=True)
        temp2={}
        try:
            temp2 = json.loads(_tprioty[1])
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, e)
        return True, temp2, _tprioty[2], _tprioty[3]

    def prioty(self, obdict): #server_addr,_name,_hash,dheader):
        if check_args(obdict, (("server",str),("name",str),("hash",str))) == False:
            return False, "check_args failed (prioty)"
        
        temp=self.get(server_addr,_name,_hash,headers=obdict["headers"])
        if temp[0]==False:
            return temp
        return self.prioty_direct(temp[1])

    #check if _addr is reachable and update priority
    def check_direct(self, obdict):
        if check_args(obdict, (("address",str),("namelocal",str),("certhash",str))) == False:
            return False, "check_args failed (check_direct)"
        dheader["certhash"]=_hash #ensure this
        
        temp = self.prioty_direct(obdict)
        if temp[0]==False:
            return temp
        if self.hashdb.exist(obdict["namelocal"],obdict["certhash"])==True:
            self.hashdb.changepriority(obdict["namelocal"],obdict["certhash"])
            self.hashdb.changetype(obdict["namelocal"],obdict["certhash"],temp[1]["type"])
        return temp
    
    #check if node is reachable and update priority
    def check(self, obdict):
        if check_args(obdict, (("server",str),("name",str),("namelocal",str),("hash",str))) == False:
            return False, "check_args failed (check)"
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        obdict["address"] = temp[1]["address"]
        return self.check_direct(obdict)
    #local management

    #search
    def searchhash(self, obdict):
        if check_args(obdict, (("certhash",str),)) == False:
            return False, "check_args failed (searchhash)"
        temp = self.hashdb.certhash_as_name(obdict["certhash"])
        if temp is None:
            return False, error
        else:
            return True,temp
            
    def getlocal(self, obdict):
        if check_args(obdict, (("name",str),("certhash",str))) == False:
            return False, "check_args failed (getlocal)"
        temp = self.hashdb.get(obdict["name"],obdict["certhash"])
        if temp is None:
            return False, "error"
        else:
            return True,temp
    
    def listhashes(self, obdict):
        if check_args(obdict, (("name",str),("filter",str))) == False:
            _name, _nodetypefilter = obdict["name"], obdict["filter"]
        elif check_args(obdict, (("name",str),)) == False:
            _name = obdict["name"]
            _nodetypefilter = None
        else:
            return False, "check_args failed (listhashes)"
        
        temp = self.hashdb.listhashes(_name, _nodetypefilter)
        if temp is None:
            return False, "error"
        else:
            return True, temp
    
    def listnodenametypes(self, obdict):
        temp = self.hashdb.listnodenametypes()
        if temp is None:
            return False, "error"
        else:
            return True, temp
    
    def listnodenames(self,obdict):
        if check_args(obdict, (("filter",str),)) == False:
            _nodetypefilter = obdict["filter"]
        else:
            return False, "check_args failed (listnodenames)"
        temp = self.hashdb.listnodenames(_nodetypefilter)
        if temp is None:
            return False, "error"
        else:
            return True,temp

    def listnodeall(self, obdict):
        if check_args(obdict, (("filter",str),)) == False:
            _nodetypefilter = obdict["filter"]
        else:
            return False, "check_args failed (listnodeall)"
        temp = self.hashdb.listnodeall(_nodetypefilter)
        if temp is None:
            return False, "error"
        else:
            return True,temp
    
    def getreferences(self, obdict):
        if check_args(obdict, (("certhash",str),("filter",str))) == False:
            _certhash, _nodetypefilter = obdict["certhash"], obdict["filter"]
        elif check_args(obdict, (("filter",str),)) == False:
            _nodetypefilter = obdict["filter"]
        else:
            return False, "check_args failed (getreferences)"
        
        if check_hash(_certhash) == True:
            _localname = self.hashdb.certhash_as_name(_certhash) #can return None to sort out invalid hashes
        else:
            _localname = None
        if _localname is None:
            return False, "certhash does not exist: {}".format(_certhash)
        _tref = self.hashdb.get(_localname, _certhash)
        if _tref is None:
            return False,"error in hashdb"
        temp = self.hashdb.getreferences(_tref[2], _reftypefilter)
        if temp is None:
            return False, "error"
        return True, temp
        
    def findbyref(self, obdict): #_reference):
        if check_args(obdict, (("reference",str),)) == False:
            return False, "check_args failed (findbyref)"
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False, "error"
        return True,temp


