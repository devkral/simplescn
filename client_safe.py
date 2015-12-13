
import ssl
from common import isself, dhash, check_argsdeco, check_args, scnparse_url,EnforcedPortFail, check_updated_certs, traverser_helper
#logger, check_hash

class client_safe(object):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "listnames", "listnodenames", "listnodeall", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref", "delservice", "open_pwrequest", "open_notify"}

    hashdb = None
    links = None
    cert_hash = None
    _cache_help = None
    validactions = None
    name = None
    sslcont = None
    brokencerts = []
    nattraversals = {}
    udpsrcsock = None
    
    
    @check_argsdeco()
    def help(self, obdict):
        """ return help """
        return True, self._cache_help
    
    @check_argsdeco({"server":(str, ),})
    def register(self, obdict):
        """ register client """
        _srvaddr = None
        if "hserver" in self.links:
            serversock = self.links["hserver"].socket
        else:
            return False, "cannot register without servercomponent"
        _srvaddr = scnparse_url(obdict.get("server"))
        if _srvaddr:
            self.nattraversals[_srvaddr] = traverser_helper(serversock.getsockname(), _srvaddr, connectsock=serversock, srcsock=self.udpsrcsock)
        ret = self.do_request(obdict.get("server"),"/server/register", body={"name":self.name, "port": serversock.getsockname()[1], "pwcall_method":obdict.get("pwcall_method"), "update": self.brokencerts}, headers=obdict.get("headers"), sendclientcert=True)
        # 
        if _srvaddr and (ret[0] != True or ret[1].get("traverse", False) == True):
            del(self.nattraversals[_srvaddr])
        return ret
    
    @check_argsdeco()
    def show(self, obdict):
        """ show client stats """
        if "hserver" in self.links:
            addr = self.links["hserver"].socket.getsockname()
            return True,{"name": self.name, "hash": self.cert_hash, "address": addr[0], "port":addr[1]}
        else:
            return True, {"name": self.name, "hash": self.cert_hash}
    
    @check_argsdeco({"name": (str, ),"port": (int, )})
    def registerservice(self, obdict):
        """ register service (second way) """
        return self.do_request("localhost-{}".format(self.links["hserver"].socket.getsockname()[1]), "/server/registerservice", obdict)
    
    @check_argsdeco({"name": (str, )})
    def delservice(self, obdict):
        """ delete service (second way) """
        return self.do_request("localhost-{}".format(self.links["hserver"].socket.getsockname()[1]), "/server/delservice", obdict)
    
    @check_argsdeco({"name": (str, "service name"), }, {"client":(str, )})
    def getservice(self, obdict):
        """ get port of a service """
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr = "localhost-{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"))
    
    @check_argsdeco(optional={"client":(str, )})
    def listservices(self, obdict):
        """ list services with ports """
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr="localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        _tservices = self.do_request(client_addr, "/server/dumpservices", body={"pwcall_method":obdict.get("pwcall_method")},  headers=obdict.get("headers"), forceport=True)
        if _tservices[0] == False:
            return _tservices
        out=sorted(_tservices[1].items(), key=lambda t: t[0])
        return _tservices[0], {"items": out, "map":["name", "port"]}, _tservices[2], _tservices[3]
    
    @check_argsdeco({"server": (str, ), "name": (str, ), "hash": (str, )})
    def get(self,obdict):
        """ fetch client address """
        #obdict["forcehash"] = obdict["hash"]
        _getret = self.do_request(obdict["server"],"/server/get", body={"pwcall_method":obdict.get("pwcall_method")},headers=obdict.get("headers"))
        if _getret[0] == False or check_args(_getret[1], {"address": (str,), "port": (int,)}) == False:
            return _getret
        if _getret[1].get("port", 0) < 1:
            return False,"port <1: {}".format(_getret[1]["port"])
        # case client runs on server
        if _getret[1]["address"] in ["::1", "127.0.0.1"]: # use serveraddress instead
            addr, port = scnparse_url(obdict["server"])
            _getret[1]["address"] = addr
        return _getret
    
    @check_argsdeco({"address": (str, ), })
    def gethash(self, obdict):
        """ fetch hash from address """
        if obdict["address"] in ["", " ", None]:
            return False, "address is empty"
        try:
            _addr = scnparse_url(obdict["address"],force_port=False)
            pcert = ssl.get_server_certificate(_addr, ssl_version=ssl.PROTOCOL_TLSv1_2).strip().rstrip()
            return True, {"hash":dhash(pcert), "cert":pcert}
        except ssl.SSLError:
            return False, "server speaks no tls 1.2"
        except ConnectionRefusedError:
            return False, "server does not exist"
        except EnforcedPortFail as e:
            return False, e.msg
        except Exception as e:
            return False, "Other error: {}:{}".format(obdict.get("address"), e)

    @check_argsdeco({"address": (str, "node (server/client) url"), })
    def ask(self, obdict):
        """ retrieve localname of a address/None if not available """
        _ha = self.gethash(obdict)
        if _ha[0] == False:
            return _ha
        if _ha[1]["hash"] == self.cert_hash:
            return True, {"localname":isself, "hash":self.cert_hash, "cert":_ha[1]["cert"]}
        
        hasho = self.hashdb.get(_ha[1]["hash"])
        if hasho:
            return True, {"localname":hasho[0],"security":hasho[3], "hash":_ha[1]["hash"], "cert":_ha[1]["cert"]}
        else:
            return True, {"hash":_ha[1]["hash"], "cert":_ha[1]["cert"]}

    @check_argsdeco({"server": (str, "server url"), })
    def listnames(self, obdict):
        """ list and sort names from server """
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", body={"pwcall_method":obdict.get("pwcall_method")},  headers=obdict.get("headers"))
        if _tnames[0] == False:
            return _tnames
        out = []
        for name, _hash, _security in sorted(_tnames[1], key=lambda t: t[0]):
            if _hash == self.cert_hash:
                out.append((name, _hash, _security, isself))
            else:
                out.append((name, _hash, _security, self.hashdb.certhash_as_name(_hash)))
        return _tnames[0], {"items": out, "map":["name", "hash", "security", "localname"]}, _tnames[2], _tnames[3]
    
    @check_argsdeco(optional={"address":(str, "node (server/client) url")})
    def info(self, obdict):
        """ retrieve info of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr=obdict["address"]
            del obdict["address"]
        else:
            _addr="localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/info", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)

    @check_argsdeco(optional={"address":(str, "node (server/client) url")})
    def cap(self, obdict):
        """ retrieve capabilities of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/cap", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)
    
    @check_argsdeco(optional={"address":(str, "node (server/client) url")})
    def prioty_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/prioty", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)

    @check_argsdeco({"server": (str, "server url"), "name": (str, "client name"), "hash": (str, "client certificate hash")})
    def prioty(self, obdict):
        """ retrieve priority and type of a client on a server """
        temp=self.get(obdict)
        if temp[0]==False:
            return temp
        return self.prioty_direct("{address}-{port}".format(**temp[1]))

    #check if _addr is reachable and update priority
    @check_argsdeco({"address": (str, "node (server/client) url"), "hash": (str, "node certificate hash")})
    def check_direct(self, obdict):
        """ retrieve priority and type of own client/remote client/server; update own priority/type information """
        temp = self.prioty_direct(obdict)
        if temp[0] == False:
            return temp
        hasho = self.hashdb.get(obdict["hash"])
        if temp[3] != obdict["hash"]:
            ret = check_updated_certs(temp[1].get("address"), temp[1].get("port"), [(obdict.get("hash"), "insecure"), ], newhash=temp[3])
            if len(ret) == 0:
                return False, "MITM attack?, Certmissmatch"
            if hasho:
                # TODO: validate that this is secure
                self.hashdb.changesecurity(obdict["hash"], "insecure")
                self.hashdb.addhash(hasho[0], temp[1].get("hash"), hasho[1], hasho[2], "unverified")
        if hasho is not None:
            self.hashdb.changepriority(obdict["hash"])
            self.hashdb.changetype(obdict["hash"],temp[1]["type"])
        return temp
    
    #check if node is reachable and update priority
    @check_argsdeco({"server":(str, "server url"),"name":(str, "client name"),"hash": (str, "client hash")})
    def check(self, obdict):
        """ retrieve priority, type, certsecuritystate of a client on a server; update own priority/type/certsecuritystate information """
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        if temp[1].get("security", "valid") != "valid":
            ret = check_updated_certs(temp[1].get("address"), temp[1].get("port"), [(obdict.get("hash"), temp[1].get("security")), ])
            if len(ret) == 0:
                return False, "MITM attack?, Certmissmatch"
            
            hasho = self.hashdb.get(obdict["hash"])
            if hasho:
                self.hashdb.changesecurity(obdict["hash"], "insecure")
                self.hashdb.addhash(hasho[0], temp[1].get("hash"), hasho[1], hasho[2], "unverified")
            
            #return False, "Certificate updated, verify"
            obdict["hash"] = temp[3]
        obdict["address"] = "{address}-{port}".format(**temp[1])
        return self.check_direct(obdict)
    
    ### local management ###

    
    @check_argsdeco({"hash":(str, "local node hash") })
    def getlocal(self, obdict):
        """ get information about entity identified by name and hash in hashdb """
        out = self.hashdb.get(obdict["hash"])
        if out is None:
            return False, "Not in db"
        ret = {
        "name": out[0],
        "type": out[1],
        "priority": out[2],
        "security": out[3],
        "certreferenceid": out[4]
        }
        return True, ret
    
    @check_argsdeco({"name":(str, "local name")}, optional={"filter":(str, "filter nodetype (server/client)")})
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
    
    @check_argsdeco(optional={"filter":(str, "filter nodetype (server/client)")})
    def listnodenames(self,obdict):
        """ list nodenames """
        temp = self.hashdb.listnodenames(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name"]}
    
    @check_argsdeco(optional={"filter":(str, "filter nodetype (server/client)")})
    def listnodeall(self, obdict):
        """ list nodes with all informations """
        temp = self.hashdb.listnodeall(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name","hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco(optional={"filter":(str, "filter reference type"), "hash": (str, "local hash (or certreferenceid)"), "certreferenceid": (int, "reference id of certificate hash (or hash)")})
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
    
    @check_argsdeco({"reference":(str, "reference")})
    def findbyref(self, obdict):
        """ find nodes in hashdb by reference """
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False, "reference does not exist: {}".format(obdict["reference"])
        return True, {"items":temp, "map": ["name","hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco({"message":(str, "message for password dialog")}, optional={"requester":(str, "plugin calling password dialog")})
    def open_pwrequest(self, obdict):
        """ open password request """
        if obdict.get("clientcert","") == "" or self.receive_redirect_hash == "" or self.receive_redirect_hash != dhash(obdict.get("clientcert","")) or self.plugin_pw_caller is None:
            return False, "auth failed"
        temp = self.plugin_pw_caller(obdict.get("message"), obdict.get("requester"))
        if temp is None:
            return True, {"pw":temp}
        else:
            return False, "auth aborted"

    @check_argsdeco({"message":(str, "message for notify dialog")}, optional={"requester":(str, "plugin calling notify dialog")})
    def open_notify(self, obdict):
        """ open notify """
        if obdict.get("clientcert","") == "" or self.receive_redirect_hash == "" or self.receive_redirect_hash != dhash(obdict.get("clientcert","")) or self.plugin_notify_caller is None:
            return False, "auth failed"
        temp = self.plugin_notify_caller(obdict.get("message"), obdict.get("requester"))
        return True, {"result": temp}
        
