
import ssl
from common import isself, check_hash, dhash, check_argsdeco, check_args, scnparse_url,EnforcedPortFail
#logger
from http import client

class client_safe(object):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "listnames", "listnodenames", "listnodeall", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref"}

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
    
    @check_argsdeco({"server":(str, ),})
    def register(self, obdict):
        """ register client """
        return self.do_request(obdict.get("server"),"/server/register", body={"name":self.name, "hash": self.cert_hash, "port": self.show(obdict)[1]["port"], "pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"))
    
    @check_argsdeco()
    def show(self, obdict):
        """ show client stats """
        if "server" in self.links:
            return True,{"name": self.name, "hash": self.cert_hash,
                "port":str(self.links["hserver"].socket.getsockname()[1])}
        else:
            return True,{"name": self.name, "hash": self.cert_hash,
                "port":str(None)}
    
    @check_argsdeco({"name": (str, ),"port": (int, )})
    def registerservice(self, obdict):
        """ register service (second way) """
        return self.do_request("localhost:{}".format(self.links["server"].socket.getsockname()[1]),"/server/registerservice", obdict)
    
    @check_argsdeco({"name": (str, )})
    def delservice(self, obdict):
        """ delete service (second way) """
        return self.do_request("localhost:{}".format(self.links["server"].socket.getsockname()[1]),"/server/delservice", obdict)
    
    @check_argsdeco({"server": (str, ), "name": (str, ), "hash": (str, )})
    def get(self,obdict):
        """ fetch client address """
        #obdict["forcehash"] = obdict["hash"]
        _getret = self.do_request(obdict["server"],"/server/get", obdict,headers=obdict.get("headers"))
        if _getret[0] == False or check_args(_getret[1], {"address": (str,), "port": (int,)}) == False:
            return _getret
        if _getret[1].get("port", 0)<1:
            return False,"port <1: {}".format(_getret[1]["port"])
        return _getret
    
    @check_argsdeco({"address": (str, ), })
    def gethash(self, obdict):
        """ fetch hash from address """
        if obdict["address"] in ["", " ", None]:
            return False, "address is empty"
        try:
            _addr = scnparse_url(obdict["address"],force_port=False)
            con = client.HTTPSConnection(_addr[0], _addr[1], context=self.sslcont)
            con.connect()
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            con.close()
            
            return True, {"hash":dhash(pcert), "cert":pcert}
        except ssl.SSLError:
            return False, "server speaks no tls 1.2"
        except ConnectionRefusedError:
            return False, "server does not exist"
        except EnforcedPortFail as e:
            return False, e.msg
        except Exception as e:
            return False, "Other error: {}:{}".format(obdict.get("address"), e)

    @check_argsdeco({"address": (str, ), })
    def ask(self, obdict):
        """ retrieve localname of a address/None if not available """
        _ha = self.gethash(obdict)
        if _ha[0] == False:
            return _ha
        if _ha[1]["hash"] == self.cert_hash:
            return True, {"localname":isself, "hash":self.cert_hash}
        temp = self.hashdb.certhash_as_name(_ha[1]["hash"])
        return True, {"localname":temp, "hash":_ha[1]["hash"], "cert":_ha[1]["cert"]}

    @check_argsdeco({"server": (str, ), })
    def listnames(self, obdict):
        """ list and sort names from server """
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", headers=obdict.get("headers"))
        if _tnames[0] == False:
            return _tnames
        out = []
        for name, _hash in sorted(_tnames[1], key=lambda t: t[0]):
            if _hash == self.cert_hash:
                out.append((name, _hash, isself))
            else:
                out.append((name, _hash, self.hashdb.certhash_as_name(_hash)))
        return _tnames[0], {"items": out, "map":["name",]}, _tnames[2], _tnames[3]
    
    @check_argsdeco({"name": (str, "service name"), }, {"client":(str, )})
    def getservice(self, obdict):
        """ get port of a service """
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice",obdict,headers=obdict.get("headers"))
    
    @check_argsdeco(optional={"client":(str, )})
    def listservices(self, obdict):
        """ list services with ports """
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        _tservices = self.do_request(client_addr, "/server/dumpservices", headers=obdict.get("headers"), forceport=True)
        if _tservices[0] == False:
            return _tservices
        out=sorted(_tservices[1].items(), key=lambda t: t[0])
        return _tservices[0], {"items": out, "map":["name", "port"]}, _tservices[2], _tservices[3]
    
    @check_argsdeco(optional={"address":(str, "url of scn communication partner")})
    def info(self, obdict):
        """ retrieve info of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr=obdict["address"]
            del obdict["address"]
        else:
            _addr="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/info", headers=obdict.get("headers"), forceport=True)

    @check_argsdeco(optional={"address":(str, "url of scn communication partner")})
    def cap(self, obdict):
        """ retrieve capabilities of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/cap", headers=obdict.get("headers"), forceport=True)
    
    @check_argsdeco(optional={"address":(str, "url of scn communication partner")})
    def prioty_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost:{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/prioty", headers=obdict.get("headers"), forceport=True)

    @check_argsdeco({"server": (str, ), "name": (str, ), "hash": (str, )})
    def prioty(self, obdict):
        """ retrieve priority and type of a client on a server """
        temp=self.get(obdict)
        if temp[0]==False:
            return temp
        return self.prioty_direct("{address}:{port}".format(**temp[1]))

    #check if _addr is reachable and update priority
    @check_argsdeco({"address": (str, ), "hash": (str, )})
    def check_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server; update own priority/type information """
        temp = self.prioty_direct(obdict)
        if temp[0] == False:
            return temp
        if self.hashdb.get(obdict["hash"]) is not None:
            self.hashdb.changepriority(obdict["hash"])
            self.hashdb.changetype(obdict["hash"],temp[1]["type"])
        return temp
    
    #check if node is reachable and update priority
    @check_argsdeco({"server":(str, ),"name":(str, ),"hash": (str, )})
    def check(self, obdict):
        """ retrieve priority and type of a client on a server; update own priority/type information """
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        obdict["address"] = temp[1]["address"]
        return self.check_direct(obdict)
    
    ### local management ###

    
    @check_argsdeco({"hash":(str, ) })
    def getlocal(self, obdict):
        """ get information about entity identified by name and hash in hashdb """
        out = self.hashdb.get(obdict["hash"])
        ret = {
        "name": out[0],
        "type": out[1],
        "priority": out[2],
        "security": out[3],
        "certreferenceid": out[4]
        }
        return True, ret
    
    @check_argsdeco({"name":(str,)}, optional={"filter":(str, )})
    def listhashes(self, obdict):
        """ list hashes in hashdb """
        _name = obdict.get("name")
        temp = self.hashdb.listhashes(_name, obdict.get("filter", None))
        
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco()
    def listnodenametypes(self, obdict):
        """ list nodenames with type """
        temp = self.hashdb.listnodenametypes()
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name", "type"]}
    
    @check_argsdeco(optional={"filter":(str, )})
    def listnodenames(self,obdict):
        """ list nodenames """
        temp = self.hashdb.listnodenames(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name"]}
    
    @check_argsdeco(optional={"filter":(str, )})
    def listnodeall(self, obdict):
        """ list nodes with all informations """
        temp = self.hashdb.listnodeall(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name","hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco(optional={"filter":(str, ), "hash": (str, ), "certreferenceid": (int, )})
    def getreferences(self, obdict):
        """ get references of a hash """
        if obdict.get("certreferenceid") is None:
            _hash = obdict.get("hash")
            _tref = self.hashdb.get( _hash)
            if _tref is None:
                return False, "certhash does not exist: {}".format(_hash)
            _tref = _tref[4]
        else:
            _tref = obdict.get("certreferenceid")
        temp = self.hashdb.getreferences(_tref, obdict.get("filter", None))
        if temp is None:
            return False
        return True, {"items":temp, "map": ["reference","type"]}
    
    @check_argsdeco({"reference":(str, )})
    def findbyref(self, obdict):
        """ find nodes in hashdb by reference """
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False, "reference does not exist: {}".format(obdict["reference"])
        return True, {"name":temp[0],"hash":temp[1],"type":temp[2],"priority":temp[3],"security":temp[4]}
