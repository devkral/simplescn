
"""
safe stuff (harm is limited, so useable for plugins) (client)
license: MIT, see LICENSE.txt
"""

import ssl
import socket
import abc
import collections


from simplescn import EnforcedPortError
from simplescn.config import isself
from simplescn.tools import dhash, scnparse_url, default_sslcont, extract_senddict, generate_error, gen_result, genc_error
from simplescn.tools.checks import check_updated_certs, check_local, check_args, namestr, hashstr, securitystr, destportint
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
            ret = self.do_request(client_addr, "/server/getservice", senddict, _headers, forcehash=_forcehash, forceport=True)
            if ret[0] and not isinstance(ret[1].get("port", None), int):
                return False, genc_error("invalid serveranswer")
            return ret
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
            return: address, port, security, traverse_needed, traverse_address, (name, hash)
            server: server url
            forcehash: enforce server with hash==forcehash
            name: client name
            hash: client hash """
        senddict = extract_senddict(obdict, "hash", "name")
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        _getret = self.do_request(obdict["server"], "/server/get", senddict, _headers, forcehash=obdict.get("forcehash"))
        if not _getret[0]:
            return _getret
        if not check_args(_getret[1], {"address": str, "port": destportint, "security": securitystr}):
            return False, genc_error("invalid serveranswer")
        # if broken cert check also this
        if _getret[1]["security"] != "valid" and not check_args(_getret[1], {"name": namestr, "hash": hashstr}):
            return False, genc_error("invalid serveranswer")

        # case: remote node runs on server
        if check_local(_getret[1]["address"]):
            # use serveraddress instead
            _getret[1]["address"] = scnparse_url(obdict["server"])[0]
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
        ret = self.do_request(_addr, "/server/trust", {"hash": hash}, _headers, \
                              forceport=True, forcehash=obdict.get("forcehash", None))
        if ret[0] and not isinstance(ret[1].get("security", None), str):
            return False, genc_error("invalid serveranswer")
        return ret

    @check_args_deco({"address": str, "name": namestr}, optional={"forcehash": hashstr})
    @classify_accessable
    def wrap(self, obdict: dict):
        """ func: initiate wrap
            return: wrapped socket
            name: service name
            forcehash: enforce node with hash==forcehash
            address: remote node url """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        return self.do_request(obdict["address"], "/wrap/{}".format(obdict["name"]), {}, \
                               _headers, forceport=True, closecon=False, sendclientcert=True, \
                               forcehash=obdict.get("forcehash", None))

    @check_args_deco({"server": str}, optional={"forcehash": hashstr})
    @classify_accessable
    def listnames(self, obdict: dict):
        """ func: sort and list names from server
            return: sorted list of client names with additional informations
            forcehash: enforce node with hash==forcehash
            server: server url """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        _tnames = self.do_request(obdict["server"], "/server/dumpnames", {}, \
                                  _headers, forcehash=obdict.get("forcehash", None))
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
            ret = self.do_request(_addr, "/server/info", {}, _headers, forcehash=_forcehash)
            if not check_args(ret[1], {"type": str, "name": namestr, "message": str}):
                return False, genc_error("invalid serveranswer")
            return ret
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
            ret = self.do_request(_addr, "/server/cap", {}, _headers, forcehash=_forcehash)
            if ret[0] and not isinstance(ret[1].get("caps", None), collections.Iterable):
                return False, genc_error("invalid serveranswer")
            return ret
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
            ret = self.do_request(_addr, "/server/prioty", {}, _headers, forcehash=_forcehash, forceport=True)
            if ret[0] and (not isinstance(ret[1].get("priority", None), int) or not isinstance(ret[1].get("type", None), str)):
                return False, genc_error("invalid serveranswer")
            return ret
        else:
            # access direct (more speed+no pwcheck)
            _cstemp = self.links["client_server"]
            return True, {"priority": _cstemp.priority, "type": _cstemp.scn_type}

    @check_args_deco({"address": str, "hash": hashstr}, optional={"security": str, "forcehash": hashstr})
    @classify_accessable
    def check_direct(self, obdict: dict):
        """ func: check if a address is reachable; update local information when reachable
            return: priority, type, certificate security; return [2][1] == new hash of client
            address: node url
            hash: node certificate hash
            forcehash: enforce node with hash==forcehash
            security: set/verify security """
        _headers = {"Authorisation": obdict.get("headers", {}).get("Authorisation", "scn {}")}
        _obdsecurity = obdict.get("security", "valid")
        if obdict["hash"] == self.links["certtupel"][1]:
            # forcehash if hash is from client itself
            if _obdsecurity != "valid":
                return False, genc_error("Error: own client is marked not valid")
            _priotydirectbody = {"address": obdict["address"], "headers": _headers, "forcehash": self.links["certtupel"][1]}
        elif "forcehash" in obdict:
             # forcehash if requested
            _priotydirectbody = {"address": obdict["address"], "headers": _headers, "forcehash": obdict["forcehash"]}
        else:
            #  elsewise handle hash mismatch later
            _priotydirectbody = {"address": obdict["address"], "headers": _headers}
        prioty_ret = self.prioty_direct(_priotydirectbody)
        if not prioty_ret[0]:
            return prioty_ret

        # handle hash mismatch (own client by use of forcehash excluded)
        if prioty_ret[2][1] != obdict["hash"]:
            assert obdict["hash"] != self.links["certtupel"][1], "should not happen because of use of forcehash"
            _newsecurity = "insecure"
        else:
            _newsecurity = _obdsecurity
        if _newsecurity != "valid":
            assert obdict["hash"] != self.links["certtupel"][1], "should not happen because client is forced to be valid"
            # add placeholder security field, init as _newsecurity
            prioty_ret[1]["security"] = _newsecurity
            address, port = scnparse_url(obdict.get("address"), False)
            check_ret = check_updated_certs(address, port, [(obdict["hash"], _newsecurity)], newhash=prioty_ret[2][1])
            if check_ret in [None, []] and _obdsecurity == "valid":
                return False, genc_error("MITM attack?, Certmismatch")
            elif check_ret in [None, []]:
                return False, genc_error("MITM?, Wrong Server information?, Certmismatch and security!=valid")
            hashgetl = self.links["hashdb"].get(obdict["hash"])
            # is in db and was valid before
            if hashgetl and hashgetl[3] == "valid":
                # invalidate old
                self.links["hashdb"].changesecurity(obdict["hash"], _newsecurity)
                # create new entry with security=="unverified" if not in db elsewise just copy references
                newhashgetl = self.links["hashdb"].get(prioty_ret[2][1])
                if not newhashgetl:
                    self.links["hashdb"].addhash(hashgetl[0], prioty_ret[2][1], hashgetl[1], hashgetl[2], "unverified")
                    newhashgetl = self.links["hashdb"].get(prioty_ret[2][1])
                # copy references
                self.links["hashdb"].copyreferences(hashgetl[4], newhashgetl[4])
                # update security field to value in db
                prioty_ret[1]["security"] = newhashgetl[3]
        else:
            # security was valid and no hash mismatch
            prioty_ret[1]["security"] = "valid"

        if obdict["hash"] != self.links["certtupel"][1]:
            self.links["hashdb"].changepriority(prioty_ret[2][1], prioty_ret[1]["priority"])
            self.links["hashdb"].changetype(prioty_ret[2][1], prioty_ret[1]["type"])
        return prioty_ret

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
