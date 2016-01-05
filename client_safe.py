
import ssl
from common import experimental, isself, dhash, check_argsdeco, check_args, scnparse_url, EnforcedPortFail, check_updated_certs

class client_safe(object):
    
    validactions_safe={"get", "gethash", "help", "show", "register", "getlocal","listhashes","listnodenametypes", "listnames", "listnodenames", "listnodeall", "getservice", "registerservice", "listservices", "info", "check", "check_direct", "prioty_direct", "prioty", "ask", "getreferences", "cap", "findbyref", "delservice"}
    if experimental:
        validactions_safe.add("open_pwrequest")
        validactions_safe.add("open_notify") # not tested and verified, so deactivate them

    hashdb = None
    links = None
    cert_hash = None
    _cache_help = None
    validactions = None
    name = None
    sslcont = None
    brokencerts = []
    udpsrcsock = None
    
    
    @check_argsdeco()
    def help(self, obdict):
        """ func: return help
            return: help """
        return True, self._cache_help
    
    @check_argsdeco({"server": str})
    def register(self, obdict):
        """ func: register client
            return: success or error
            server: address of server """
        _srvaddr = None
        if "hserver" in self.links:
            serversock = self.links["hserver"].socket
        else:
            return False, "cannot register without servercomponent"
        _srvaddr = scnparse_url(obdict.get("server"))
        if _srvaddr:
            self.scntraverse_helper.add_desttupel(_srvaddr)
        ret = self.do_request(obdict.get("server"),"/server/register", body={"name":self.name, "port": serversock.getsockname()[1], "pwcall_method":obdict.get("pwcall_method"), "update": self.brokencerts}, headers=obdict.get("headers"), sendclientcert=True)
        # 
        if _srvaddr and (ret[0] != True or ret[1].get("traverse", False) == True):
             self.scntraverse_helper.del_desttupel(_srvaddr)
        return ret
    
    @check_argsdeco()
    def show(self, obdict):
        """ func: show client stats
            return: client stats """
        if "hserver" in self.links:
            addr = self.links["hserver"].socket.getsockname()
            return True,{"name": self.name, "hash": self.cert_hash, "address": addr[0], "port":addr[1]}
        else:
            return True, {"name": self.name, "hash": self.cert_hash}
    
    @check_argsdeco({"name": str, "port": int})
    def registerservice(self, obdict):
        """ func: register service (second way)
            return: success or error
            name: service name
            port: port number """
        return self.do_request("localhost-{}".format(self.links["hserver"].socket.getsockname()[1]), "/server/registerservice", obdict)
    
    @check_argsdeco({"name": str})
    def delservice(self, obdict):
        """ func: delete service (second way)
            return: success or error
            name: service name """
        return self.do_request("localhost-{}".format(self.links["hserver"].socket.getsockname()[1]), "/server/delservice", obdict)
    
    @check_argsdeco({"name": str}, {"client": str})
    def getservice(self, obdict):
        """ func: get port of a service
            return: port of service
            name: service name
            client: client url """
        if obdict.get("client") == False:
            client_addr = obdict["client"]
            del obdict["client"]
        else:
            client_addr = "localhost-{}".format(self.links["server"].socket.getsockname()[1])
        return self.do_request(client_addr, "/server/getservice", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"))
    
    @check_argsdeco(optional={"client": str})
    def listservices(self, obdict):
        """ func: list services with ports
            return port, service pairs
            client: client url (default: own client) """
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
    
    @check_argsdeco({"server": str, "name": str, "hash": str})
    def get(self, obdict):
        """ func: fetch client address from server
            return: client address
            server: server url
            name: client name
            hash: client hash """
        #obdict["forcehash"] = obdict["hash"]
        _getret = self.do_request(obdict["server"],"/server/get", body={"pwcall_method":obdict.get("pwcall_method"), "hash":obdict.get("hash"), "name":obdict.get("name")},headers=obdict.get("headers"))
        if _getret[0] == False or check_args(_getret[1], {"address": str, "port": int}) == False:
            return _getret
        if _getret[1].get("port", 0) < 1:
            return False,"port <1: {}".format(_getret[1]["port"])
        # case client runs on server
        if _getret[1]["address"] in ["::1", "127.0.0.1"]: # use serveraddress instead
            addr, port = scnparse_url(obdict["server"])
            _getret[1]["address"] = addr
        return _getret
    
    @check_argsdeco({"address": str})
    def gethash(self, obdict):
        """ func: fetch hash from address
            return: hash, certificate (stripped = scn compatible)
            address: node url """
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

    @check_argsdeco({"address": str})
    def ask(self, obdict):
        """ func: retrieve localname of a address/None if not available
            return: local information about remote url
            address: node url """
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

    @check_argsdeco({"server": str})
    def listnames(self, obdict):
        """ func: sort and list names from server
            return: sorted list of client names with additional informations
            server: server url """
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
    
    @check_argsdeco(optional={"address": str})
    def info(self, obdict):
        """ func: retrieve info of node
            return: info section
            address: remote node url (default: own client) """
        if obdict.get("address") is not None:
            _addr=obdict["address"]
            del obdict["address"]
        else:
            _addr="localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/info", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)

    @check_argsdeco(optional={"address": str})
    def cap(self, obdict):
        """ func: retrieve capabilities of node
            return: info section
            address: remote node url (default: own client) """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/cap", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)
    
    @check_argsdeco(optional={"address": str})
    def prioty_direct(self, obdict):
        """ func: retrieve priority of node
            return: info section
            address: remote node url (default: own client) """
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            del obdict["address"]
        else:
            _addr = "localhost-{}".format(self.links["hserver"].socket.getsockname()[1])
        return self.do_request(_addr, "/server/prioty", body={"pwcall_method":obdict.get("pwcall_method")}, headers=obdict.get("headers"), forceport=True)

    @check_argsdeco({"server": str, "name": str, "hash": str})
    def prioty(self, obdict):
        """ func: retrieve priority and type of a client on a server
            return: priority and type
            server: server url
            name: client name
            hash: client hash """
        temp=self.get(obdict)
        if temp[0]==False:
            return temp
        return self.prioty_direct({"address":"{address}-{port}".format(**temp[1])})

    @check_argsdeco({"address": str, "hash": str})
    def check_direct(self, obdict):
        """ func: check if a address is reachable; update local information when reachable
            return: priority, type, missing: certificate security
            address: node url
            hash: node certificate hash """
        temp = self.prioty_direct(obdict)
        if temp[0] == False:
            return temp
        hashdbo = self.hashdb.get(obdict["hash"])
        if temp[3] != obdict["hash"]:
            ret = check_updated_certs(temp[1].get("address"), temp[1].get("port"), [(obdict.get("hash"), "insecure"), ], newhash=temp[3])
            if len(ret) == 0:
                return False, "MITM attack?, Certmissmatch"
            if hashdbo:
                # TODO: validate that this is secure
                self.hashdb.changesecurity(obdict["hash"], "insecure")
                self.hashdb.addhash(hashdbo[0], temp[1].get("hash"), hashdbo[1], hashdbo[2], "unverified")
        if hashdbo:
            self.hashdb.changepriority(obdict["hash"], temp[1]["priority"])
            self.hashdb.changetype(obdict["hash"], temp[1]["type"])
            if temp[3] != obdict["hash"]:
                temp[1]["security"] = "unverified"
            else:
                temp[1]["security"] = hashdbo[3]
        return temp
    
    @check_argsdeco({"server": str,"name": str, "hash": str})
    def check(self, obdict):
        """ func: check if client is reachable; update local information when reachable
            return: priority, type, certificate security
            server: server url
            hash: client certificate hash """
        temp = self.get(obdict)
        if temp[0] == False:
            return temp
        if temp[1].get("security", "valid") != "valid":
            ret = check_updated_certs(temp[1].get("address"), temp[1].get("port"), [(obdict.get("hash"), temp[1].get("security")), ])
            if len(ret) == 0:
                return False, "MITM attack?, Certmissmatch"
            hashdbo = self.hashdb.get(obdict["hash"])
            if hashdbo:
                self.hashdb.changesecurity(obdict["hash"], "insecure")
                self.hashdb.addhash(hashdbo[0], temp[1].get("hash"), hashdbo[1], hashdbo[2], "unverified")
            #return False, "Certificate updated, verify"
            obdict["hash"] = temp[3]
        obdict["address"] = "{address}-{port}".format(**temp[1])
        return self.check_direct(obdict)
    
    ### local management ###

    @check_argsdeco({"hash": str})
    def getlocal(self, obdict):
        """ func: retrieve local information about hash (hashdb)
            return: local information about certificate hash
            hash: node certificate hash """
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
    
    @check_argsdeco({"name": str}, optional={"filter": str})
    def listhashes(self, obdict):
        """ func: list hashes in hashdb
            return: list with local informations
            name: entity name
            filter: filter nodetype (server/client) (default: all) """
        _name = obdict.get("name")
        temp = self.hashdb.listhashes(_name, obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco()
    def listnodenametypes(self, obdict):
        """ func: list entity names with type
            return: name, type list """
        temp = self.hashdb.listnodenametypes()
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name", "type"]}
    
    @check_argsdeco(optional={"filter": str})
    def listnodenames(self,obdict):
        """ func: list entity names
            return: list entity names
            filter: filter nodetype (server/client) (default: all) """
        temp = self.hashdb.listnodenames(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name"]}
    
    @check_argsdeco(optional={"filter": str})
    def listnodeall(self, obdict):
        """ func: list nodes with all informations
            return: list with nodes with all information
            filter: filter nodetype (server/client) (default: all) """
        temp = self.hashdb.listnodeall(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["name","hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco(optional={"filter": str, "hash": str, "certreferenceid": int})
    def getreferences(self, obdict):
        """ func: get references of a node certificate hash
            return: 
            hash: local hash (or use certreferenceid)
            certreferenceid: reference id of certificate hash (or use hash)")
            filter: filter reference type """
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
    
    @check_argsdeco({"reference": str})
    def findbyref(self, obdict):
        """ func:find nodes in hashdb by reference
            return: certhash with additional informations
            reference: reference """
        temp = self.hashdb.findbyref(obdict["reference"])
        if temp is None:
            return False, "reference does not exist: {}".format(obdict["reference"])
        return True, {"items":temp, "map": ["name","hash","type","priority","security","certreferenceid"]}
    
    @check_argsdeco({"message": str}, optional={"requester": str})
    def open_pwrequest(self, obdict):
        """ func: open password dialog
            return: pw or None, or error when not allowed
            message: message for the password dialog
            requester: plugin calling the password dialog (default: None=main application) """
        if obdict.get("clientcert","") == "" or self.receive_redirect_hash == "" or self.receive_redirect_hash != dhash(obdict.get("clientcert","")) or self.plugin_pw_caller is None:
            return False, "auth failed"
        temp = self.plugin_pw_caller(obdict.get("message"), obdict.get("requester"))
        if temp is None:
            return True, {"pw":temp}
        else:
            return False, "auth aborted"

    # result contains result of notify dialog
    @check_argsdeco({"message": str}, optional={"requester": str})
    def open_notify(self, obdict):
        """ func: open notification dialog
            return: True or False, or error when not allowed
            message: message for the notification dialog
            requester: plugin calling the notification dialog (default: None=main application) """
        if obdict.get("clientcert","") == "" or self.receive_redirect_hash == "" or self.receive_redirect_hash != dhash(obdict.get("clientcert","")) or self.plugin_notify_caller is None:
            return False, "auth failed"
        temp = self.plugin_notify_caller(obdict.get("message"), obdict.get("requester"))
        return True, {"result": temp}
        
