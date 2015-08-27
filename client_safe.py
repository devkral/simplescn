
import ssl
from common import isself, check_hash, dhash, check_argsdeco, check_args
#, logger
from http import client

class client_safe(object):
    
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
        return self.do_request(obdict.get("server"),"/server/register", body={"name":self.name, "hash": self.cert_hash, "port": self.show(obdict)[1]["port"], "pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"))
    
    @check_argsdeco()
    def show(self, obdict):
        """ show client stats """
        return True,{"name": self.name, "hash": self.cert_hash,
                "port":str(self.links["server"].socket.getsockname()[1])}
    
    @check_argsdeco((("name", str),("port", int)))
    def registerservice(self, obdict):
        """ register service (second way) """
        self.do_request("localhost:{}".format(self.links["server"].socket.getsockname()[1]),"/server/registerservice", obdict)
    
    @check_argsdeco((("name", str),))
    def delservice(self, obdict):
        """ delete service (second way) """
        return self.do_request("localhost:{}".format(self.links["server"].socket.getsockname()[1]),"/server/delservice", obdict)
    
    @check_argsdeco((("server", str),("name", str),("hash", str)))
    def get(self,obdict):
        """ fetch client address """
        #obdict["forcehash"] = obdict["hash"]
        _getret = self.do_request(obdict["server"],"/server/get", obdict,headers=obdict.get("headers"))
        if _getret[0] == False or check_args(_getret[1], (("address", str), ("port", int))) == False:
            return _getret
        if _getret[1].get("port", 0)<1:
            return False,"port <1: {}".format(_getret[1]["port"])
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
        if _ha[1]["hash"] == self.cert_hash:
            return True, {"localname":isself, "hash":self.cert_hash}
        temp = self.hashdb.certhash_as_name(_ha[1]["hash"])
        return True, {"localname":temp, "hash":_ha[1]["hash"], "cert":_ha[1]["cert"]}

    @check_argsdeco((("server",str),))
    def listnames(self, obdict):
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", headers=obdict.get("headers"))
        if _tnames[0] == False:
            return _tnames
        out=sorted(_tnames[1], key=lambda t: t[0])
        return _tnames[0], out, _tnames[1], _tnames[2]
    
    @check_argsdeco((("name", str),), (("client", str),)) 
    def getservice(self, obdict):
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice",obdict,headers=obdict.get("headers"))
    
    @check_argsdeco((), (("client", str),)) 
    def listservices(self, obdict):
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        _tservices = self.do_request(client_addr, "/server/dumpservices", headers=obdict.get("headers"), forceport=True)
        if _tservices[0] == False:
            return _tservices
        out=sorted(_tservices[1], key=lambda t: t[0])
        return _tservices[0], out, _tservices[1], _tservices[2]
    
    @check_argsdeco((), (("address", str),))
    def info(self, obdict):
        """ retrieve info of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr=obdict["address"]
            del obdict["address"]
        else:
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/info", headers=obdict.get("headers"), forceport=True)

    @check_argsdeco((), (("address",str),))
    def cap(self, obdict):
        """ retrieve capabilities of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/cap", headers=obdict.get("headers"), forceport=True)
    
    @check_argsdeco((), (("address",str),))
    def prioty_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr,  "/server/prioty", headers=obdict.get("headers"), forceport=True)

    @check_argsdeco((("server", str), ("name", str), ("hash", str)))
    def prioty(self, obdict):
        """ retrieve priority and type of a client on a server """
        temp=self.get(obdict["server"],obdict["name"],obdict["hash"],headers=obdict.get("headers"))
        if temp[0]==False:
            return temp
        return self.prioty_direct(temp[1])

    #check if _addr is reachable and update priority
    @check_argsdeco((("address", str), ("namelocal", str), ("hash", str)))
    def check_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server; update own priority/type information """
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
        """ retrieve priority and type of a client on a server; update own priority/type information """
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        obdict["address"] = temp[1]["address"]
        return self.check_direct(obdict)
    
    ### local management ###

    @check_argsdeco((("hash",str),))
    def searchhash(self, obdict):
        """ search hash (of a certificate) in hashdb """
        temp = self.hashdb.certhash_as_name(obdict["hash"])
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("name",str), ),(("hash",str), ))
    def getlocal(self, obdict):
        """ get information about entity identified by name and hash in hashdb """
        temp = self.hashdb.get(obdict["name"],obdict["hash"])
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("name",str),),(("filter",str), ))
    def listhashes(self, obdict):
        """ list hashes in hashdb """
        _name = obdict.get("name")
        _nodetypefilter = obdict.get("filter")
        
        temp = self.hashdb.listhashes(_name, _nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco()
    def listnodenametypes(self, obdict):
        """ list nodenames with type """
        temp = self.hashdb.listnodenametypes()
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((), (("filter",str),))
    def listnodenames(self,obdict):
        """ list nodenames """
        _nodetypefilter = obdict.get("filter", None)
        temp = self.hashdb.listnodenames(_nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp

    @check_argsdeco((), (("filter",str),))
    def listnodeall(self, obdict):
        """ list nodes with all informations """
        _nodetypefilter = obdict.get("filter", None)
        temp = self.hashdb.listnodeall(_nodetypefilter)
        if temp is None:
            return False
        else:
            return True, temp
    
    @check_argsdeco((("hash",str),), (("filter",str),))
    def getreferences(self, obdict):
        """ get references of a hash """
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
        """ find nodes in hashdb by reference """
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False
        return True, temp

