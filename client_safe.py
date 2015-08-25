
import ssl
#import abc
from common import isself, check_hash, dhash, check_argsdeco, check_args
#, logger
from http import client

class client_safe(object): #abc.ABC):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "searchhash","listnames", "listnodenames", "listnodeall", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref"}

    hashdb = None
    links = None
    cert_hash = None
    _cache_help = None
    validactions = None
    name = None
    sslcont = None
    @check_argsdeco()
    def help(self, obdict):
        """ return help """
        return True, self._cache_help
    
    @check_argsdeco((("server",str),))
    def register(self, obdict):
        """ register client """
        return self.do_request(obdict("server"),"/server/register", {"name":self.name, "hash": self.cert_hash, "port": self.show()[1]["port"]}, obdict["header"])
    
    @check_argsdeco()
    def show(self, obdict):
        """ show client stats """
        return True,{"name": self.name, "hash": self.cert_hash,
                "port":str(self.links["server"].socket.getsockname()[1])}
    
    #### second way to add a service ####
    @check_argsdeco((("service", str),("port", int)))
    def registerservice(self, obdict):
        """ register service (second way) """
        self.links["client_server"].spmap[obdict["service"]] = obdict["port"]
        return True,"service registered"
    
    #### second way to delete a service ####
    @check_argsdeco((("service", str),))
    def delservice(self, obdict):
        """ delete service (second way) """
        if obdict["service"] in self.links["client_server"].spmap:
            del self.links["client_server"].spmap[obdict["service"]]
        return True,"service deleted"
    
    @check_argsdeco((("server", str),("name", str),("hash", str)))
    def get(self,obdict):
        """ fetch client address """
        obdict["forcehash"] = obdict["hash"]
        _getret = self.do_request(obdict["server"],"/server/get", obdict,obdict["headers"])
        if _getret[0] == False or check_args(_getret[1], (("address", str), ("port", int))) == False:
            return _getret
        if _getret[1]["port"]<1:
            return False,"port <1:\n{}".format(_getret[1]["port"])
        return _getret
    
    @check_argsdeco((("address",str),))
    def gethash(self, obdict):
        try:
            con = client.HTTPSConnection(obdict["address"], context=self.sslcont)
            con.connect()
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            con.close()
            return True, {"hash":dhash(pcert), "cert":pcert}
        except ssl.SSLError:
            return False, "server speaks no tls 1.2"
        except ConnectionRefusedError:
            return False, "server does not exist"
        except Exception as e:
            return False, "Other error: {}".format(e)

    @check_argsdeco((("address",str),))
    def ask(self, obdict):
        _ha = self.gethash(obdict["address"])
        if _ha[0] == False:
            return _ha
        if _ha[1]["certhash"] == self.cert_hash:
            return True, {"localname":isself, "hash":self.cert_hash}
        temp = self.hashdb.certhash_as_name(_ha[1]["hash"])
        return True, {"localname":temp, "hash":_ha[1]["hash"], "cert":_ha[1]["cert"]}

    @check_argsdeco((("server",str),))
    def listnames(self, obdict):
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", headers=obdict["headers"])
        if _tnames[0] == False:
            return _tnames
        out=sorted(_tnames[1], key=lambda t: t[0])
        return _tnames[0], out, _tnames[1], _tnames[2]
    
    @check_argsdeco((("service", str),), (("client", str),)) 
    def getservice(self, obdict):
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice",obdict,headers=obdict["headers"])
    
    @check_argsdeco((), (("client", str),)) 
    def listservices(self, obdict):
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        _tservices = self.do_request(client_addr, "/server/dumpservices", headers=obdict["headers"], forceport=True)
        if _tservices[0] == False:
            return _tservices
        out=sorted(_tservices[1], key=lambda t: t[0])
        return _tservices[0], out, _tservices[1], _tservices[2]
    
    @check_argsdeco((), (("address", str),))
    def info(self, obdict):
        if obdict.get("address") is not None:
            _addr=obdict["address"]
            del obdict["address"]
        else:
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/info", headers=obdict["headers"], forceport=True)

    @check_argsdeco((), (("address",str),))
    def cap(self, obdict):
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/cap", headers=obdict["headers"], forceport=True)
    
    @check_argsdeco((), (("address",str),))
    def prioty_direct(self, obdict):
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr,  "/server/prioty", headers=obdict["headers"], forceport=True)

    @check_argsdeco((("server", str), ("name", str), ("hash", str)))
    def prioty(self, obdict):
        temp=self.get(obdict["server"],obdict["name"],obdict["hash"],headers=obdict["headers"])
        if temp[0]==False:
            return temp
        return self.prioty_direct(temp[1])

    #check if _addr is reachable and update priority
    @check_argsdeco((("address", str), ("namelocal", str), ("hash", str)))
    def check_direct(self, obdict):
        temp = self.prioty_direct(obdict)
        if temp[0] == False:
            return temp
        if self.hashdb.exist(obdict["namelocal"],obdict["hash"])==True:
            self.hashdb.changepriority(obdict["namelocal"],obdict["hash"])
            self.hashdb.changetype(obdict["namelocal"],obdict["hash"],temp[1]["type"])
        return temp
    
    #check if node is reachable and update priority
    @check_argsdeco((("server",str),("name",str),("namelocal",str),("hash",str)))
    def check(self, obdict):
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        obdict["address"] = temp[1]["address"]
        return self.check_direct(obdict)
    #local management

    #search
    @check_argsdeco((("hash",str),))
    def searchhash(self, obdict):
        temp = self.hashdb.certhash_as_name(obdict["hash"])
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("name",str), ),(("hash",str), ))
    def getlocal(self, obdict):
        temp = self.hashdb.get(obdict["name"],obdict["hash"])
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("name",str),),(("filter",str), ))
    def listhashes(self, obdict):
        _name = obdict.get("name")
        _nodetypefilter = obdict.get("filter")
        
        temp = self.hashdb.listhashes(_name, _nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco()
    def listnodenametypes(self, obdict):
        temp = self.hashdb.listnodenametypes()
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((), (("filter",str),))
    def listnodenames(self,obdict):
        _nodetypefilter = obdict.get("filter", None)
        temp = self.hashdb.listnodenames(_nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp

    @check_argsdeco((), (("filter",str),))
    def listnodeall(self, obdict):
        _nodetypefilter = obdict.get("filter", None)
        temp = self.hashdb.listnodeall(_nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("hash",str),), (("filter",str),))
    def getreferences(self, obdict):
        if obdict.get("file") is not None:
            _hash, _reftypefilter = obdict["hash"], obdict["filter"]
        else:
            _hash = obdict["hash"]
        if check_hash(_hash) == True:
            _localname = self.hashdb.certhash_as_name(_hash) #can return None to sort out invalid hashes
        else:
            _localname = None
        if _localname is None:
            return False, "certhash does not exist: {}".format(_hash)
        _tref = self.hashdb.get(_localname, _hash)
        if _tref is None:
            return False,"error in hashdb"
        temp = self.hashdb.getreferences(_tref[2], _reftypefilter)
        if temp is None:
            return False
        return True, temp
    
    @check_argsdeco((("reference",str),))
    def findbyref(self, obdict):
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False
        return True, temp


