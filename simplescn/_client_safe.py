
"""
safe stuff (harm is limited, so useable for plugins) (client)
license: MIT, see LICENSE.txt
"""

import ssl
import socket
import abc


from simplescn import EnforcedPortError
from simplescn.config import isself
from simplescn.tools import dhash, scnparse_url, default_sslcont, extract_senddict, generate_error, gen_result, genc_error
from simplescn.tools.checks import check_updated_certs, check_local, check_args, namestr, hashstr
from simplescn._decos import check_args_deco, classify_local, classify_accessable

#@generate_validactions_deco
class ClientClientSafe(object, metaclass=abc.ABCMeta):
    @property
    def validactions(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def links(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def _cache_help(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def brokencerts(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def scntraverse_helper(self):
        raise NotImplementedError

    @abc.abstractmethod
    def do_request(self, _addr_or_con, _path, body, headers, forceport=False, forcehash=None, sendclientcert=False, closecon=True):
        raise NotImplementedError

    @check_args_deco()
    @classify_local
    @classify_accessable
    def help(self, obdict: dict):
        """ func: return help
            return: help """
        return True, {"help": self._cache_help}

    @check_args_deco()
    @classify_local
    @classify_accessable
    def show(self, obdict: dict):
        """ func: show client stats
            return: client stats """
            #; port==0 -> unixsockets are used, not True for hserver
        return True, {"name": self.links["client_server"].name,
                      "hash": self.links["certtupel"][1],
                      "listen": self.links["hserver"].server_address,
                      "port": self.links["hserver"].server_port}

    @check_args_deco({"server": str}, optional={"forcehash": hashstr})
    @classify_accessable
    def register(self, obdict: dict):
        """ func: register client
            forcehash: enforce node with hash==forcehash
            return: success or error
            server: address of server """
        _srvaddr = None
        server_port = self.links["hserver"].server_port
        _srvaddr = scnparse_url(obdict.get("server"))
        if not _srvaddr:
            return False, genc_error("not a valid server")
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        body = {"name": self.links["client_server"].name, "port": server_port, "update": self.brokencerts}
        ret = self.do_request(obdict.get("server"), "/server/register", body, _headers, sendclientcert=True, forcehash=obdict.get("forcehash"))

        if ret[0] and ret[1].get("traverse", False):
            self.scntraverse_helper.add_desttupel(_srvaddr)
        return ret

    @check_args_deco({"name": namestr, "port": int}, optional={"client": str, "wrappedport": bool, "post": bool, "hidden": bool, "forcehash": hashstr})
    @classify_accessable
    def registerservice(self, obdict: dict):
        """ func: register service (second way)
            return: success or error
            name: service name
            port: port number
            forcehash: enforce node with hash==forcehash
            wrappedport: port is masked/is not traversable (but can be wrapped)
            hidden: port and servicename are not listed (default: False)
            post: send http post request with certificate in header to service
            client: LOCAL client url (default: own client) """
        senddict = extract_senddict(obdict, "name", "port")
        senddict["wrappedport"] = obdict.get("wrappedport", False)
        senddict["post"] = obdict.get("post", False)
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("client") is not None:
            client_addr = obdict["client"]
            _forcehash = obdict.get("forcehash", None)
            return self.do_request(client_addr, "/server/registerservice", senddict, _headers, forcehash=_forcehash, forceport=True)
        else:
            # access direct (more speed+no pwcheck)
            senddict["clientaddress"] = ("::1", 0)
            _cstemp = self.links["client_server"]
            ret = _cstemp.registerservice(senddict, prefix=None)
            return ret[0], gen_result(ret[1])

    @check_args_deco({"name": namestr}, optional={"client": str, "forcehash": hashstr})
    @classify_accessable
    def delservice(self, obdict: dict):
        """ func: delete service (second way)
            return: success or error
            name: service name
            forcehash: enforce node with hash==forcehash
            client: LOCAL client url (default: own client) """
        senddict = extract_senddict(obdict, "name")
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("client") is not None:
            client_addr = obdict["client"]
            _forcehash = obdict.get("forcehash", None)
            return self.do_request(client_addr, "/server/delservice", senddict, _headers, forcehash=_forcehash, forceport=True)
        else:
            # access direct (more speed+no pwcheck)
            senddict["clientaddress"] = ("::1", 0)
            _cstemp = self.links["client_server"]
            ret = _cstemp.delservice(senddict, prefix=None)
            return ret[0], gen_result(ret[1])

    @check_args_deco({"name": namestr}, optional={"client": str, "forcehash": hashstr})
    @classify_accessable
    def getservice(self, obdict: dict):
        """ func: get port of a service
            return: port of service
            name: service name
            forcehash: enforce node with hash==forcehash
            client: client url (default: own client) """
        senddict = extract_senddict(obdict, "name")
        _headers = {"Authorisation":obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("client") is not None:
            client_addr = obdict["client"]
            _forcehash = obdict.get("forcehash", None)
            return self.do_request(client_addr, "/server/getservice", senddict, _headers, forcehash=_forcehash, forceport=True)
        else:
            # access direct (more speed+no pwcheck)
            _cstemp = self.links["client_server"]
            ret = _cstemp.getservice(senddict)
            return ret[0], gen_result(ret[1])

    @check_args_deco(optional={"client": str, "forcehash": hashstr})
    @classify_accessable
    def listservices(self, obdict: dict):
        """ func: list services with ports
            return port, service pairs
            forcehash: enforce node with hash==forcehash
            client: client url (default: own client) """
        _headers = {"Authorisation":obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("client") is not None:
            client_addr = obdict["client"]
            _forcehash = obdict.get("forcehash", None)
            _tservices = self.do_request(client_addr, "/server/dumpservices", {}, _headers, forcehash=_forcehash, forceport=True)
        else:
            # access direct (more speed+no pwcheck)
            _tservices = True, {"dict": self.links["client_server"].spmap}, self.links["certtupel"]
        if not _tservices[0]:
            return _tservices
        # crash if "dict" is not available instead of silently ignore error (catched)
        out = sorted(_tservices[1]["dict"].items(), key=lambda t: t[0])
        return _tservices[0], {"items": out, "map": ["name", "port"]}, _tservices[2]

    @check_args_deco({"server": str, "name": namestr, "hash": hashstr}, optional={"forcehash": hashstr})
    @classify_accessable
    def get(self, obdict: dict):
        """ func: fetch client address from server
            return: address, port, name, security, hash, traverse_needed, traverse_address
            server: server url
            forcehash: enforce server with hash==forcehash
            name: client name
            hash: client hash """
        senddict = extract_senddict(obdict, "hash", "name")
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        _getret = self.do_request(obdict["server"], "/server/get", senddict, _headers, forcehash=obdict.get("forcehash"))
        if not _getret[0] or not check_args(_getret[1], {"address": str, "port": int}):
            return _getret
        if _getret[1].get("port", 0) < 1:
            return False, "port < 1: {}".format(_getret[1]["port"])
        # case: client runs on server
        if check_local(_getret[1]["address"]):
            # use serveraddress instead
            addr, port = scnparse_url(obdict["server"])
            _getret[1]["address"] = addr
        return _getret

    @check_args_deco({"address": str})
    @classify_accessable
    def gethash(self, obdict: dict):
        """ func: fetch hash from address
            return: hash, certificate (stripped = scn compatible)
            address: node url """
        if obdict["address"] in ["", " ", None]:
            return False, genc_error("address is empty")
        try:
            cont = default_sslcont()
            _addr = scnparse_url(obdict["address"], force_port=False)
            sock = socket.create_connection(_addr)
            sslsock = cont.wrap_socket(sock, server_side=False)
            pcert = ssl.DER_cert_to_PEM_cert(sslsock.getpeercert(True)).strip().rstrip()
            return True, {"hash": dhash(pcert), "cert": pcert}
        except ssl.SSLError:
            return False, genc_error("server speaks no tls 1.2")
        except ConnectionRefusedError:
            return False, genc_error("server does not exist")
        except EnforcedPortError as exc:
            return False, generate_error(exc, False)
        except Exception as exc:
            #logging.error(exc)
            return False, generate_error(exc, True)

    @check_args_deco({"hash": hashstr, "address": str}, optional={"forcehash": hashstr})
    @classify_accessable
    def trust(self, obdict: dict):
        """ func: retrieve trust info of node, use getlocal for local node
            return: security info of node by remote client
            forcehash: enforce node with hash==forcehash
            address: remote node url """
        _addr = obdict["address"]
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        return self.do_request(_addr, "/server/trust", {"hash": hash}, _headers, forceport=True, forcehash=obdict.get("forcehash", None))

    @check_args_deco({"address": str, "name": namestr}, optional={"forcehash": hashstr})
    @classify_accessable
    def wrap(self, obdict: dict):
        """ func: initiate wrap
            return: wrapped socket
            name: service name
            forcehash: enforce node with hash==forcehash
            address: remote node url """
        _addr = obdict["address"]
        _name = obdict["name"]
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        return self.do_request(_addr, "/wrap/{}".format(_name), {}, _headers, forceport=True, closecon=False, sendclientcert=True, forcehash=obdict.get("forcehash", None))

    @check_args_deco({"server": str}, optional={"forcehash": hashstr})
    @classify_accessable
    def listnames(self, obdict: dict):
        """ func: sort and list names from server
            return: sorted list of client names with additional informations
            forcehash: enforce node with hash==forcehash
            server: server url """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", {}, _headers, forcehash=obdict.get("forcehash", None))
        if not _tnames[0]:
            return _tnames
        out = []
        # crash if "items" is not available instead of silently ignore error (catched)
        for name, _hash, _security in sorted(_tnames[1]["items"], key=lambda t: t[0]):
            if _hash == self.links["certtupel"][1]:
                out.append((name, _hash, _security, isself))
            else:
                out.append((name, _hash, _security, self.links["hashdb"].certhash_as_name(_hash)))
        return _tnames[0], {"items": out, "map": ["name", "hash", "security", "localname"]}, _tnames[2]

    @check_args_deco(optional={"address": str, "forcehash": hashstr})
    @classify_accessable
    def info(self, obdict: dict):
        """ func: retrieve info of node
            return: info section
            forcehash: enforce node with hash==forcehash
            address: remote node url (default: own client) """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            _forcehash = obdict.get("forcehash", None)
            return self.do_request(_addr, "/server/info", {}, _headers, forcehash=_forcehash)
        else:
            # access direct (more speed+no pwcheck)
            _cstemp = self.links["client_server"]
            return True, {"type": _cstemp.scn_type, "name": _cstemp.name, "message": _cstemp.message}

    @check_args_deco(optional={"address": str, "forcehash": hashstr})
    @classify_accessable
    def cap(self, obdict: dict):
        """ func: retrieve capabilities of node
            return: info section
            forcehash: enforce node with hash==forcehash
            address: remote node url (default: own client) """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            _forcehash = obdict.get("forcehash", None)
            return self.do_request(_addr, "/server/cap", {}, _headers, forcehash=_forcehash)
        else:
            # access direct (more speed+no pwcheck)
            _cstemp = self.links["client_server"]
            return True, {"caps": _cstemp.capabilities}

    @check_args_deco(optional={"address": str, "forcehash": hashstr})
    @classify_accessable
    def prioty_direct(self, obdict: dict):
        """ func: retrieve priority of node
            return: info section
            forcehash: enforce node with hash==forcehash
            address: remote node url (default: own client) """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if obdict.get("address") is not None:
            _addr = obdict["address"]
            _forcehash = obdict.get("forcehash")
            return self.do_request(_addr, "/server/prioty", {}, _headers, forcehash=_forcehash, forceport=True)
        else:
            # access direct (more speed+no pwcheck)
            _cstemp = self.links["client_server"]
            return True, {"priority": _cstemp.priority, "type": _cstemp.scn_type}


    @check_args_deco({"server": str, "name": namestr, "hash": hashstr})
    @classify_accessable
    def prioty(self, obdict: dict):
        """ func: retrieve priority and type of a client on a server
            return: priority and type
            server: server url
            name: client name
            hash: client hash """
        temp = self.get(obdict)
        if not temp[0]:
            return temp
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        return self.prioty_direct({"address":"{address}-{port}".format(**temp[1]), "forcehash": obdict["hash"], "headers":_headers})

    @check_args_deco({"address": str, "hash": hashstr}, optional={"security": str, "forcehash": hashstr})
    @classify_accessable
    def check_direct(self, obdict: dict):
        """ func: check if a address is reachable; update local information when reachable
            return: priority, type, certificate security; return [2][1] == new hash of client
            address: node url
            hash: node certificate hash
            forcehash: enforce node with hash==forcehash
            security: set/verify security """
        # force hash if hash is from client itself
        if obdict["hash"] == self.links["certtupel"][1]:
            _forcehash = self.links["certtupel"][1]
            if obdict.get("security", "valid") != "valid":
                return False, genc_error("Error: own client is marked not valid")
        else:
            _forcehash = obdict.get("forcehash", None)
        # only use forcehash if requested elsewise handle hash mismatch later
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if _forcehash:
            prioty_ret = self.prioty_direct({"address": obdict["address"], "headers": _headers, "forcehash": _forcehash})
        else:
            prioty_ret = self.prioty_direct({"address": obdict["address"], "headers": _headers})
        if not prioty_ret[0]:
            return prioty_ret
        # don't query if hash is from client itself
        if obdict["hash"] == self.links["certtupel"][1]:
            hashdbo = None
        else:
            hashdbo = self.links["hashdb"].get(obdict["hash"])
        # handle hash mismatch
        if prioty_ret[2][1] != obdict["hash"] or obdict.get("security", "valid") != "valid":
            address, port = scnparse_url(obdict.get("address"), False)
            check_ret = check_updated_certs(address, port, [(obdict.get("hash"), "insecure"), ], newhash=prioty_ret[2][1])
            if check_ret in [None, []] and obdict.get("security", "valid") == "valid":
                return False, genc_error("MITM attack?, Certmismatch")
            elif check_ret in [None, []]:
                return False, genc_error("MITM?, Wrong Server information?, Certmismatch and security!=valid")
            if obdict.get("security", "valid") == "valid":
                obdict["security"] = "insecure"
            # is in db and was valid before
            if hashdbo and hashdbo[3] == "valid":
                # invalidate old
                self.links["hashdb"].changesecurity(obdict["hash"], obdict.get("security", "insecure"))
                # create unverified new, if former state was valid and is not in db
                newhashdbo = self.links["hashdb"].get(prioty_ret[2][1])
                if not newhashdbo:
                    self.links["hashdb"].addhash(hashdbo[0], prioty_ret[2][1], hashdbo[1], hashdbo[2], "unverified")
                    newhashdbo = self.links["hashdb"].get(prioty_ret[2][1])
                # copy references
                self.links["hashdb"].copyreferences(hashdbo[4], newhashdbo[4])
                # replace hashdbo by newhashdbo
                hashdbo = newhashdbo
        # add security field, init as unverified
        prioty_ret[1]["security"] = "unverified"
        if hashdbo:
            # is hashdbo/newhashdbo in db
            self.links["hashdb"].changepriority(prioty_ret[2][1], prioty_ret[1]["priority"])
            self.links["hashdb"].changetype(prioty_ret[2][1], prioty_ret[1]["type"])
            # return security of current hash
            prioty_ret[1]["security"] = hashdbo[3]
        elif obdict["hash"] == self.links["certtupel"][1]:
            # is client itself
            # valid because (hashdbo=None)
            prioty_ret[1]["security"] = "valid"
        return prioty_ret

    # reason for beeing seperate from get: to detect if a minor or a bigger error happened
    @check_args_deco({"server": str, "name": namestr, "hash": hashstr}, optional={"forcehash": hashstr})
    @classify_accessable
    def check(self, obdict: dict):
        """ func: check if client is reachable; update local information when reachable
            return: priority, type, certificate security, (new-)hash (client)
            server: server url
            forcehash: enforce server with hash==forcehash
            name: client name
            hash: client certificate hash """
        get_ret = self.get(obdict)
        if not get_ret[0]:
            return get_ret
        # request forcehash if not valid
        if get_ret[1].get("security", "valid") != "valid":
            _forcehash = get_ret[1].get("hash")
        else:
            _forcehash = None
        newaddress = "{address}-{port}".format(**get_ret[1])
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        if _forcehash:
            direct_ret = self.check_direct({"address": newaddress, "hash": obdict["hash"], "headers": _headers, "forcehash": _forcehash, "security": get_ret[1].get("security", "valid")})
        else:
            direct_ret = self.check_direct({"address": newaddress, "hash": obdict["hash"], "headers": _headers, "security": get_ret[1].get("security", "valid")})
        # return new hash in hash field
        if direct_ret[0]:
            direct_ret[1]["hash"] = direct_ret[2][1]
        return direct_ret[0], direct_ret[1], get_ret[2]
    ### local management ###
    @check_args_deco({"name": namestr}, optional={"hash": hashstr})
    @classify_local
    @classify_accessable
    def exist(self, obdict: dict):
        """ func: retrieve local information about hash (hashdb)
            return: local information about certificate hash
            hash: node certificate hash """
        return self.links["hashdb"].exist(obdict["name"], obdict.get("hash", None))

    @check_args_deco({"hash": hashstr})
    @classify_local
    @classify_accessable
    def getlocal(self, obdict: dict):
        """ func: retrieve local information about hash (hashdb)
            return: local information about certificate hash
            hash: node certificate hash """
        out = self.links["hashdb"].get(obdict["hash"])
        if out is None:
            return False, genc_error("Not in db")
        ret = \
        {
            "name": out[0],
            "type": out[1],
            "priority": out[2],
            "security": out[3],
            "certreferenceid": out[4]
        }
        return True, ret

    @check_args_deco({"name": namestr}, optional={"filter": str})
    @classify_local
    @classify_accessable
    def listhashes(self, obdict: dict):
        """ func: list hashes in hashdb
            return: list with local informations
            name: entity name
            filter: filter nodetype (server/client) (default: all) """
        temp = self.links["hashdb"].listhashes(obdict["name"], obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items":temp, "map": ["hash", "type", "priority", "security", "certreferenceid"]}

    @check_args_deco()
    @classify_local
    @classify_accessable
    def listnodenametypes(self, obdict: dict):
        """ func: list entity names with type
            return: name, type list """
        temp = self.links["hashdb"].listnodenametypes()
        if temp is None:
            return False
        else:
            return True, {"items": temp, "map": ["name", "type"]}

    @check_args_deco(optional={"filter": str})
    @classify_local
    @classify_accessable
    def listnodenames(self, obdict: dict):
        """ func: list entity names
            return: list entity names
            filter: filter nodetype (server/client) (default: all) """
        temp = self.links["hashdb"].listnodenames(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items": temp, "map": ["name"]}

    @check_args_deco(optional={"filter": str})
    @classify_local
    @classify_accessable
    def listnodeall(self, obdict: dict):
        """ func: list nodes with all informations
            return: list with nodes with all information
            filter: filter nodetype (server/client) (default: all) """
        temp = self.links["hashdb"].listnodeall(obdict.get("filter", None))
        if temp is None:
            return False
        else:
            return True, {"items": temp, "map": ["name", "hash", "type", "priority", "security", "certreferenceid"]}

    @check_args_deco(optional={"filter": str, "hash": hashstr, "certreferenceid": int})
    @classify_local
    @classify_accessable
    def getreferences(self, obdict: dict):
        """ func: get references of a node certificate hash
            return: reference, referencetype list for hash/referenceid
            hash: local hash (or use certreferenceid)
            certreferenceid: reference id of certificate hash (or use hash)
            filter: filter reference type """
        if "certreferenceid" in obdict :
            _tref = obdict.get("certreferenceid")
        elif "hash" in obdict :
            _trethash = self.links["hashdb"].get(obdict["hash"])
            if _trethash is None:
                return False, genc_error("hash not exist")
            _tref = _trethash[4]
        else:
            return False, genc_error("neither hash nor certreferenceid given")
        temp = self.links["hashdb"].getreferences(_tref, obdict.get("filter", None))
        if temp is None:
            return False
        return True, {"items": temp, "map": ["reference", "type"]}

    @check_args_deco({"reference": str}, optional={"filter": str})
    @classify_local
    @classify_accessable
    def findbyref(self, obdict: dict):
        """ func:find nodes in hashdb by reference
            return: certhash with additional informations
            reference: reference """
        temp = self.links["hashdb"].findbyref(obdict["reference"], obdict.get("filter", None))
        if temp is None:
            return False, genc_error("error looking up reference")
        return True, {"items": temp, "map": ["name", "hash", "type", "priority", "security", "certreferenceid"]}
