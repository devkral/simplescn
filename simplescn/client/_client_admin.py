
"""
admin stuff (client)
license: MIT, see LICENSE.txt
"""

import os
import sys
import threading
import logging
import abc

from ..config import isself
from ..tools import dhash, generate_certs, quick_error
from ..tools.checks import check_reference_type, namestr, permissionstr, \
hashstr, priorityint, namelist, hashlist, securitystr, addressstr, referencestr
from .._decos import classify_admin, classify_local, check_args_deco, classify_accessable

def _mipcheck_inlisthelper(_name, _hash, entities, hashes):
    """ massimport helper """
    if not entities and not hashes:
        return True
    if entities and _name in entities:
        return True
    if hashes and _hash in hashes:
        return True
    return False

#@generate_validactions_deco
class ClientClientAdmin(object, metaclass=abc.ABCMeta):
    @property
    def validactions(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def links(self):
        raise NotImplementedError

    @abc.abstractmethod
    def do_request(self, addr_or_con, path: str, body, headers: dict, forceport=False, forcehash=None, \
                sendclientcert=False, closecon=True, traverseaddress=None):
        raise NotImplementedError

    writeMsgLock = None
    changeNameLock = None

    def __init__(self):
        self.writeMsgLock = threading.Lock()
        self.changeNameLock = threading.Lock()

    @check_args_deco({"priority": priorityint})
    @classify_admin
    @classify_local
    @classify_accessable
    def setpriority(self, obdict: dict):
        """ func: set priority of client
            return: success or error
            priority: priority of the client"""
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_cache()
        return True

    #local management
    @check_args_deco({"name": namestr})
    @classify_admin
    @classify_local
    @classify_accessable
    def addentity(self, obdict: dict):
        """ func: add entity (=named group for hashes)
            return: success or erro
            name: entity name """
        return self.links["hashdb"].addentity(obdict["name"])

    @check_args_deco({"name": namestr})
    @classify_admin
    @classify_local
    @classify_accessable
    def delentity(self, obdict: dict):
        """ func: delete entity (=named group for hashes)
            return: success or error
            name: entity name """
        return self.links["hashdb"].delentity(obdict["name"])

    @check_args_deco({"name": namestr, "newname": namestr})
    @classify_admin
    @classify_local
    @classify_accessable
    def renameentity(self, obdict: dict):
        """ func: rename entity (=named group for hashes)
            return success or error
            name: entity name
            newname: new entity name """
        return self.links["hashdb"].renameentity(obdict["name"], obdict["newname"])

    @check_args_deco({"name": namestr, "hash": hashstr}, optional={"type": str, "priority": int})
    @classify_admin
    @classify_local
    @classify_accessable
    def addhash(self, obdict: dict):
        """ func: add hash to entity (=named group for hashes)
            return: success or error
            name: entity name
            hash: certificate hash
            type: type (=client/server/notimagined yet)
            priority: initial priority """
        _type = obdict.get("type", "unknown")
        _priority = obdict.get("priority", 20)
        _name, _certhash = obdict["name"], obdict["hash"]
        return self.links["hashdb"].addhash(_name, _certhash, _type, _priority)

    @check_args_deco({"hash": hashstr})
    @classify_admin
    @classify_local
    @classify_accessable
    def delhash(self, obdict: dict):
        """ func: delete hash
            return: success or error
            hash: certificate hash (=part of entity) """
        return self.links["hashdb"].delhash(obdict["hash"])

    @check_args_deco({"hash": hashstr, "security": securitystr})
    @classify_admin
    @classify_local
    @classify_accessable
    def changesecurity(self, obdict: dict):
        """ func: change security level of hash
            return: success or error
            hash: certificate hash (=part of entity)
            security: security level """
        return self.links["hashdb"].changesecurity(obdict["hash"], obdict["security"])

    @check_args_deco({"hash": hashstr, "newname": namestr})
    @classify_admin
    @classify_local
    @classify_accessable
    def movehash(self, obdict: dict):
        """ func: move hash to entity
            return: success or error
            hash: certificate hash (=part of entity)
            newname: entity where hash should moved to """
        return self.links["hashdb"].movehash(obdict["hash"], obdict["newname"])

    @check_args_deco({"hash": hashstr, "reference": referencestr, "reftype": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def addreference(self, obdict: dict):
        """ func: add reference (=child of hash) to hash
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)
            reftype: reference type """
        if not check_reference_type(obdict["reftype"]):
            return False, quick_error("reference type invalid")
        _tref = self.links["hashdb"].get(obdict["hash"])
        if _tref is None:
            return False, quick_error("hash not found")
        return self.links["hashdb"].addreference(_tref[4], obdict["reference"], obdict["reftype"])

    @check_args_deco({"hash": hashstr, "reference": referencestr, "newreference": referencestr, "newreftype": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def updatereference(self, obdict: dict):
        """ func: update reference (=child of hash)
            return: success or error
            hash: certificate hash (=part of entity)
            reference: old reference (=reference to update)
            newreference: new reference (=new location)
            newreftype: new reference type """
        if not check_reference_type(obdict["newreftype"]):
            return False, quick_error("reference type invalid")
        _tref = self.links["hashdb"].get(obdict["hash"])
        if _tref is None:
            return False, quick_error("hash not found")
        return self.links["hashdb"].updatereference(_tref[4], obdict["reference"], obdict["newreference"], obdict["newreftype"])

    @check_args_deco({"hash": hashstr, "reference": referencestr})
    @classify_admin
    @classify_local
    @classify_accessable
    def delreference(self, obdict: dict):
        """ func: delete reference (=child of hash)
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)"""
        _tref = self.links["hashdb"].get(obdict["hash"])
        if _tref is None:
            return False, quick_error("hash not found")
        return self.links["hashdb"].delreference(_tref[4], obdict["reference"])

    @check_args_deco({"reason": securitystr})
    @classify_admin
    @classify_local
    @classify_accessable
    def invalidatecert(self, obdict: dict):
        """ func: invalidate certificate
            return: success or error
            reason: reason (=security level) for invalidating cert"""
        if obdict.get("reason") == "valid":
            return False, quick_error("wrong reason")
        self.delperm({"hash": self.links["certtupel"][1]})
        _cpath = os.path.join(self.links["config_root"], "client_cert")
        if os.path.isfile(_cpath+".pub"):
            with open(_cpath+".pub", "r") as readob:
                _hash = dhash(readob.read().strip().rstrip())
            _brokenpath = os.path.join(self.links["config_root"], "broken", _hash)
            if os.path.isfile(_cpath+".priv"):
                os.rename(_cpath+".pub", _brokenpath+".pub")
            else:
                os.remove(_cpath+".pub")
            os.rename(_cpath+".priv", _brokenpath+".priv")
            with open(_brokenpath+".reason", "w") as wr:
                wr.write(obdict.get("reason"))
        else:
            return False, quick_error("no pubcert")
        ret = generate_certs(_cpath)
        if not ret:
            logging.critical("Fatal error: certs could not be regenerated")
            # in case logger is catched and handler doesn't output
            print("Fatal error: certs could not be regenerated", file=sys.stderr)
            sys.exit(1)
        with open(_cpath+".pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip()
        self.links["certtupel"] = (isself, dhash(pub_cert), pub_cert)
        self.links["hserver"].shutdown()
        self.links["hserver"].socket.close()
        print("Keydestruction successful - Please restart process")
        sys.exit(0)
        #return True

    @check_args_deco({"message": str}, optional={"permanent": bool})
    @classify_admin
    @classify_local
    @classify_accessable
    def changemsg(self, obdict: dict):
        """ func: change message
            return: success or error
            message: new message
            permanent: permanent or just temporary (cleared when closing client) (default: True) """
        configr = self.links["config_root"]
        with self.writeMsgLock:
            if obdict.get("permanent", True):
                with open(os.path.join(configr, "client_message.txt"), "w") as wm:
                    wm.write(obdict.get("message"))
            self.links["client_server"].message = obdict.get("message")
            self.links["client_server"].update_cache()
            return True

    @check_args_deco({"loglevel": int})
    @classify_admin
    @classify_local
    @classify_accessable
    def changeloglevel(self, obdict: dict):
        """ func: change loglevel
            return: success or error
            loglevel: name of loglevel """
        logging.root.setLevel(obdict["loglevel"])
        return True

    @check_args_deco({"name": namestr}, optional={"permanent": bool})
    @classify_admin
    @classify_local
    @classify_accessable
    def changename(self, obdict: dict):
        """ func: change name
            return: success or error
            name: client name
            permanent: permanent or just temporary (cleared when closing client) (default: True) """
        with self.changeNameLock:
            newname = obdict["name"]
            if obdict.get("permanent", True):
                configr = self.links["config_root"]
                oldt = None
                with open(os.path.join(configr, "client_name.txt"), "r") as readn:
                    oldt = readn.read().strip().rstrip().split("/")
                if oldt is None:
                    return False, quick_error("reading name failed")
                with open(os.path.join(configr, "client_name.txt"), "w") as writen:
                    if len(oldt) == 2:
                        writen.write("{}/{}".format(newname, oldt[1]))
                    else:
                        writen.write("{}/0".format(newname))
            self.links["client_server"].name = newname
            self.links["client_server"].update_cache()
            return True

    @check_args_deco({"hash": hashstr, "permission": permissionstr})
    @classify_admin
    @classify_local
    def addperm(self, obdict):
        """ func: add permissions for certhash to permsdb
            return: success or error
            hash: certhash of trusted
            permission: which permission """
        return self.links["permsdb"].add(obdict["hash"], obdict["permission"])

    @check_args_deco({"hash": hashstr}, optional={"permission": permissionstr})
    @classify_admin
    @classify_local
    def delperm(self, obdict):
        """ func: delete permission(s) certhash from permsdb
            return: success or error
            hash: certhash of trusted
            permission: which permission (default: None=all) """
        return self.links["permsdb"].delete(obdict["hash"], obdict.get("permission", None))

    @check_args_deco({"hash": hashstr})
    @classify_admin
    @classify_local
    def getperm(self, obdict):
        """ func: get permissions certhash from permsdb
            return: list permissions of certhash
            hash: certhash of trusted """
        ret = self.links["permsdb"].get(obdict["hash"], None)
        if ret is None:
            return False, quick_error("retrieving permission(s) failed")
        return True, {"items": ret, "map": ["permission"]}

    @check_args_deco({"sourceaddress": addressstr, "sourcehash": hashstr}, optional={"entities": namelist, "hashes": hashlist, "traverseaddress": addressstr, "traversepw": hashstr})
    @classify_admin
    @classify_accessable
    def massimport(self, obdict: dict):
        """ func: import hashes and entities
            return: success or error
            sourceaddress: address of source (client)
            sourcehash: hash of source
            traverseaddress: server for traversal
            traversepw: dhashed pw for traversal server
            entities: list with entities to import (imports hashes below), None for all
            hashes: list with hashes to import (imports references below), None for all """
        travaddr = obdict.get("traverseaddress", None)
        travpw = obdict.get("traversepw", None)
        listall = self.do_request(obdict["sourceaddress"], \
                                  "/client/listnodeall", {}, {}, \
                                  forcehash=obdict["sourcehash"], \
                                  closecon=False, sendclientcert=True, \
                                  traverseaddress=travaddr, \
                                  traversepw=travpw)
        if not listall[0]:
            return listall
        _imp_ent = obdict.get("entities")
        _imp_hash = obdict.get("hashes")
        for _name, _hash, _type, _priority, _security, _certreferenceid in listall[1]["items"]:
            if _name not in namestr:
                logging.warning("invalid name %s", _name)
                continue

            if _hash != "default" and _hash not in hashstr:
                logging.warning("invalid hash %s", _hash)
                continue
            if not _mipcheck_inlisthelper(_name, _hash, _imp_ent, _imp_hash):
                continue
            if not self.links["hashdb"].exist(_name):
                self.links["hashdb"].addentity(_name)

            # skip placeholder
            if _hash == "default":
                continue

            if self.links["hashdb"].exist(_name, _hash):
                pass
                #self.links["hashdb"].updatehash(_hash, _type, _priority, _security)
            elif self.links["hashdb"].get(_hash):
                # don't update references of certhash which is already in db and not explicitly specified by name,hash
                # or by hash in hashes
                if not _imp_hash or _hash not in _imp_hash:
                    continue
            else:
                self.links["hashdb"].addhash(_name, _hash, _type, _priority, _security)
            localref = self.links["hashdb"].get(_hash)
            if localref is None:
                return False, quick_error("could not write entry")
            localreferences = self.links["hashdb"].getreferences(localref[4])
            # reuse connection
            # retransmit clientcert after connection loss, e.g. Connection close
            # sendclientcert=False is default (certinfo persists serverside)
            _retreferences = self.do_request(listall[1]["wrappedcon"], "/client/getreferences", \
                                             {"hash": _hash}, {}, forcehash=obdict["sourcehash"], \
                                             closecon=False, \
                                             sendclientcert=listall[1]["wrappedcon"].sock is None, \
                                             traverseaddress=travaddr, \
                                             traversepw=travpw)
            if not _retreferences[0]:
                logging.error(_retreferences[1])
                continue
            for _ref, _reftype in _retreferences[1]["items"]:
                if (_ref, _reftype) in localreferences:
                    pass
                else:
                    self.links["hashdb"].addreference(localref[4], _ref, _reftype)
        return True
