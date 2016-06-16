
"""
admin stuff (client)
license: MIT, see LICENSE.txt
"""

import os
import sys
import threading
import logging
import abc

from simplescn.tools import dhash, generate_certs
from simplescn.tools.checks import check_reference, check_reference_type, check_name, check_security
from simplescn._decos import classify_admin, classify_local, check_args_deco, classify_accessable, generate_validactions_deco

@generate_validactions_deco
class client_admin(object, metaclass=abc.ABCMeta):
    @property
    def validactions(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def hashdb(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def links(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def cert_hash(self):
        raise NotImplementedError

    @abc.abstractmethod
    def do_request(self, _addr_or_con, _path, body=None, headers=None, forceport=False, forcehash=None, forcetraverse=False, sendclientcert=False):
        raise NotImplementedError

    writeMsgLock = None
    changeNameLock = None

    def __init__(self):
        self.writeMsgLock = threading.Lock()
        self.changeNameLock = threading.Lock()

    @check_args_deco({"priority": int})
    @classify_admin
    @classify_local
    @classify_accessable
    def setpriority(self, obdict: dict):
        """ func: set priority of client
            return: success or error
            priority: priority of the client"""
        if obdict["priority"] < 0 or obdict["priority"] > 100:
            return False, "out of range"
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_cache()
        return True

    #local management
    @check_args_deco({"name": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def addentity(self, obdict: dict):
        """ func: add entity (=named group for hashes)
            return: success or erro
            name: entity name """
        return self.hashdb.addentity(obdict["name"])

    @check_args_deco({"name": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def delentity(self, obdict: dict):
        """ func: delete entity (=named group for hashes)
            return: success or error
            name: entity name """
        return self.hashdb.delentity(obdict["name"])

    @check_args_deco({"name": str, "newname": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def renameentity(self, obdict: dict):
        """ func: rename entity (=named group for hashes)
            return success or error
            name: entity name
            newname: new entity name """
        return self.hashdb.renameentity(obdict["name"], obdict["newname"])

    @check_args_deco({"name": str, "hash": str}, optional={"type": str, "priority": int})
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
        return self.hashdb.addhash(_name, _certhash, _type, _priority)

    @check_args_deco({"hash": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def delhash(self, obdict: dict):
        """ func: delete hash
            return: success or error
            hash: certificate hash (=part of entity) """
        return self.hashdb.delhash(obdict["hash"])

    @check_args_deco({"hash": str, "security": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def changesecurity(self, obdict: dict):
        """ func: change security level of hash
            return: success or error
            hash: certificate hash (=part of entity)
            security: security level """
        return self.hashdb.changesecurity(obdict["hash"], obdict["security"])

    @check_args_deco({"hash": str, "newname": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def movehash(self, obdict: dict):
        """ func: move hash to entity
            return: success or error
            hash: certificate hash (=part of entity)
            newname: entity where hash should moved to """
        return self.hashdb.movehash(obdict["hash"], obdict["newname"])

    # don't expose to other plugins, at least not without question
    # other plugins could check for insecure plugins
    @check_args_deco()
    @classify_admin
    @classify_local
    @classify_accessable
    def listplugins(self, obdict: dict):
        """ func: list plugins
            return: plugins """
        pluginm = self.links["client_server"].pluginmanager
        out = sorted(pluginm.list_plugins().keys())
        ret = []
        for plugin in out:
            ret.append((plugin, pluginm.plugin_is_active(plugin)))
        return True, {"items": ret, "map": ["plugin", "state"]}

    @check_args_deco({"hash": str, "reference": str, "reftype": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def addreference(self, obdict: dict):
        """ func: add reference (=child of hash) to hash
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)
            reftype: reference type """
        _name = self.hashdb.certhash_as_name(obdict["hash"])
        if _name is None:
            return False, "hash not in db: {}".format(obdict["hash"])
        if not check_reference(obdict["reference"]):
            return False, "reference invalid"
        if not check_reference_type(obdict["reftype"]):
            return False, "reference type invalid"
        _tref = self.hashdb.get(obdict["hash"])
        return self.hashdb.addreference(_tref[4], obdict["reference"], obdict["reftype"])

    @check_args_deco({"hash": str, "reference": str, "newreference": str, "newreftype": str})
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
        if not check_reference(obdict["newreference"]):
            return False, "reference invalid"
        if not check_reference_type(obdict["newreftype"]):
            return False, "reference type invalid"
        _tref = self.hashdb.get(obdict["hash"])
        if _tref is None:
            return False, "hash not exist"
        return self.hashdb.updatereference(_tref[4], obdict["reference"], obdict["newreference"], obdict["newreftype"])

    @check_args_deco({"hash": str, "reference": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def delreference(self, obdict: dict):
        """ func: delete reference (=child of hash)
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)"""
        _tref = self.hashdb.get(obdict["hash"])
        if _tref is None:
            return False, "hash not exist"
        return self.hashdb.delreference(_tref[4], obdict["reference"])

    @check_args_deco({"reason": str})
    @classify_admin
    @classify_local
    @classify_accessable
    def invalidatecert(self, obdict: dict):
        """ func: invalidate certificate
            return: success or error
            reason: reason (=security level) for invalidating cert"""
        if not check_security(obdict.get("reason")) or obdict.get("reason") == "valid":
            return False, "wrong reason"
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
            return False, "no pubcert"
        ret = generate_certs(_cpath)
        if not ret:
            logging.critical("Fatal error: certs could not be regenerated")
            # in case logger is catched and handler doesn't output
            print("Fatal error: certs could not be regenerated", file=sys.stderr)
            sys.exit(1)
        with open(_cpath+".pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip()
        self.links["client"].cert_hash = dhash(pub_cert)
        self.links["client_server"].cert_hash = dhash(pub_cert)
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

    @check_args_deco({"name": str}, optional={"permanent": bool})
    @classify_admin
    @classify_local
    @classify_accessable
    def changename(self, obdict: dict):
        """ func: change name
            return: success or error
            name: client name
            permanent: permanent or just temporary (cleared when closing client) (default: True) """
        with self.changeNameLock:
            newname = obdict.get("name")
            if not check_name(newname):
                return False, "not a valid name"
            if obdict.get("permanent", True):
                configr = self.links["config_root"]
                oldt = None
                with open(os.path.join(configr, "client_name.txt"), "r") as readn:
                    oldt = readn.read().strip().rstrip().split("/")
                if oldt is None:
                    return False, "reading name failed"
                with open(os.path.join(configr, "client_name.txt"), "w") as writen:
                    if len(oldt) == 2:
                        writen.write("{}/{}".format(newname, oldt[1]))
                    else:
                        writen.write("{}/0".format(newname))
            self.links["client"].name = newname
            self.links["client_server"].name = newname
            self.links["client_server"].update_cache()
            return True

    # TODO: test
    @check_args_deco({"sourceaddress": str, "sourcehash": str, "entities": list, "hashes": list})
    @classify_admin
    @classify_accessable
    def massimporter(self, obdict: dict):
        """ func: import hashes and entities
            return: success or error
            sourceaddress: address of source (client)
            sourcehash: hash of source
            entities: list with entities to import (imports hashes below), None for all
            hashes: list with hashes to import (imports references below) """
        #listhashes = obdict.get("hashes")
        listall = self.do_request(obdict.get("sourceaddress"), "/client/listnodeall", forcehash=obdict.get("sourcehash"))
        _imp_ent = obdict.get("entities")
        _imp_hash = obdict.get("hashes")
        for _name, _hash, _type, _priority, _security, _certreferenceid in listall:
            if _imp_ent is not None and _name not in _imp_ent and _hash not in _imp_hash:
                continue
            if not self.hashdb.exists(_name):
                self.hashdb.addentity(_name)
            if self.hashdb.exists(_name, _hash):
                pass
                #self.hashdb.updatehash(_hash, _type, _priority, _security)
            elif self.hashdb.get(_hash) is not None:
                pass
            else:
                self.hashdb.addhash(_name, _hash, _type, _priority, _security)
            localref = self.hashdb.get(_hash)
            if localref is None:
                return False, "could not write entry"
            else:
                localref = localref[4]
            localreferences = self.hashdb.getreferences(localref)
            _retreferences = self.do_request(obdict.get("client"), "/client/getreferences", {"hash":_hash})
            if _retreferences[0]:
                for _ref, _reftype in _retreferences[1]["items"]:
                    if (_ref, _reftype) in localreferences:
                        pass
                    else:
                        self.hashdb.addreference(localref, _ref, _reftype)
        return True, "import finished"

