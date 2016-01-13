
import os, sys
import threading
#isself
from simplescn.client_config import client_config
from simplescn.common import check_reference, check_reference_type, check_argsdeco, check_name, check_security, dhash, generate_certs, logger, classify_admin, classify_experimental, classify_noplugin, classify_local

class client_admin(object): 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "addreference", "updatereference", "delreference", "listplugins", "changemsg", "changename", "invalidatecert", "changesecurity", "requestredirect", "massimporter"}
    
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    write_msg_lock = None
    change_name_lock = None
    
    def __init__(self):
        self.write_msg_lock = threading.Lock()
        self.change_name_lock = threading.Lock()
    
    
    @check_argsdeco({"priority": int})
    @classify_admin
    @classify_local
    def setpriority(self, obdict):
        """ func: set priority of client
            return: success or error
            priority: priority of the client""" 
        if obdict["priority"]<0 or obdict["priority"]>100:
            return False, "out of range"
        
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_cache()
        return True
        
    #local management
    
    @check_argsdeco({"name": str})
    @classify_admin
    @classify_local
    def addentity(self, obdict):
        """ func: add entity (=named group for hashes)
            return: success or erro
            name: entity name """
        return self.hashdb.addentity(obdict["name"])

    
    @check_argsdeco({"name": str})
    @classify_admin
    @classify_local
    def delentity(self, obdict):
        """ func: delete entity (=named group for hashes)
            return: success or error
            name: entity name """
        return self.hashdb.delentity(obdict["name"])

    
    @check_argsdeco({"name": str, "newname": str})
    @classify_admin
    @classify_local
    def renameentity(self, obdict):
        """ func: rename entity (=named group for hashes)
            return success or error
            name: entity name
            newname: new entity name """
        return self.hashdb.renameentity(obdict["name"],obdict["newname"])

    
    @check_argsdeco({"name": str,"hash": str}, optional={"type": str, "priority": int})
    @classify_admin
    @classify_local
    def addhash(self, obdict):
        """ func: add hash to entity (=named group for hashes)
            return: success or error
            name: entity name
            hash: certificate hash
            type: type (=client/server/notimagined yet)
            priority: initial priority """
        _type = obdict.get("type", "unknown")
        _priority = obdict.get("priority", 20)
        _name,  _certhash = obdict["name"], obdict["hash"]
        return self.hashdb.addhash(_name, _certhash, _type, _priority)

    
    @check_argsdeco({"hash": str})
    @classify_admin
    @classify_local
    def delhash(self, obdict):
        """ func: delete hash
            return: success or error
            hash: certificate hash (=part of entity) """
        return self.hashdb.delhash(obdict["hash"])
    
    
    
    @check_argsdeco({"hash": str, "security": str})
    @classify_admin
    @classify_local
    def changesecurity(self, obdict):
        """ func: change security level of hash
            return: success or error
            hash: certificate hash (=part of entity)
            security: security level """
        return self.hashdb.changesecurity(obdict["hash"],obdict["security"])
    
    
    @check_argsdeco({"hash": str, "newname": str})
    @classify_admin
    @classify_local
    def movehash(self, obdict):
        """ func: move hash to entity
            return: success or error
            hash: certificate hash (=part of entity)
            newname: entity where hash should moved to """
        return self.hashdb.movehash(obdict["hash"],obdict["newname"])
    
    # don't expose to other plugins, at least not without question
    # other plugins could check for insecure plugins
    
    @check_argsdeco()
    @classify_admin
    @classify_noplugin
    @classify_local
    def listplugins(self, obdict):
        """ func: list plugins
            return: plugins """
        pluginm = self.links["client_server"].pluginmanager
        out = sorted(pluginm.list_plugins().items())
        ret = []
        for plugin, path in out:
            ret.append((plugin, pluginm.plugin_is_active(plugin)))
        return True, {"items":ret,"map":["plugin","state"]}
    
    
    @check_argsdeco({"hash": str, "reference": str, "reftype": str})
    @classify_admin
    @classify_local
    def addreference(self, obdict):
        """ func: add reference (=child of hash) to hash
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)
            reftype: reference type """
        _name=self.hashdb.certhash_as_name(obdict["hash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["hash"])
        
        if check_reference(obdict["reference"])==False:
            return False, "reference invalid"
        if check_reference_type(obdict["reftype"])==False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(obdict["hash"])
        return self.hashdb.addreference(_tref[4],obdict["reference"],obdict["reftype"])

    
    @check_argsdeco({"hash": str, "reference": str, "newreference": str, "newreftype": str})
    @classify_admin
    @classify_local
    def updatereference(self, obdict):
        """ func: update reference (=child of hash)
            return: success or error
            hash: certificate hash (=part of entity)
            reference: old reference (=reference to update)
            newreference: new reference (=new location)
            newreftype: new reference type """
        if check_reference(obdict["newreference"]) == False:
            return False, "reference invalid"
        
        if check_reference_type(obdict["newreftype"]) == False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(obdict["hash"])
        if _tref is None:
            return False,"hash not exist"
        
        return self.hashdb.updatereference(_tref[4],obdict["reference"],obdict["newreference"],obdict["newreftype"])

    
    @check_argsdeco({"hash": str, "reference": str})
    @classify_admin
    @classify_local
    def delreference(self, obdict):
        """ func: delete reference (=child of hash)
            return: success or error
            hash: certificate hash (=part of entity)
            reference: reference (=where to find node)"""
        _tref=self.hashdb.get(obdict["hash"])
        if _tref is None:
            return False, "hash not exist"
        return self.hashdb.delreference(_tref[4],obdict["reference"])

    
    @check_argsdeco({"reason": str})
    @classify_admin
    @classify_local
    def invalidatecert(self, obdict):
        """ func: invalidate certificate
            return: success or error
            reason: reason (=security level) for invalidating cert"""
        if check_security(obdict.get("reason")) == False or obdict.get("reason") == "valid":
            return False, "wrong reason"
        _cpath = os.path.join(self.links["config_root"],"client_cert")
        
        if os.path.isfile(_cpath+".pub"):
            with open(_cpath+".pub", "r") as re:
                _hash = dhash(re.read().strip().rstrip())
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
        if ret == False:
            logger().critical("Fatal error: certs could not be regenerated")
            # in case logger is catched and handler doesn't output
            print("Fatal error: certs could not be regenerated")
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

    
    @check_argsdeco({"message": str},optional={"permanent": bool})
    @classify_admin
    @classify_local
    def changemsg(self, obdict):
        """ func: change message
            return: success or error
            message: new message
            permanent: permanent or just temporary (cleared when closing client) (default: True) """
        #_type = self.links.get("client_server").scn_type
        configr = self.links["config_root"]
        with self.write_msg_lock:
            self.links["client_server"].message = obdict.get("message")
            self.links["client_server"].update_cache()
            if obdict.get("permanent", True):
                with open(os.path.join(configr,"client_message.txt"), "w") as wm:
                    wm.write(obdict.get("message"))
        return True
    
    
    @check_argsdeco({"name": str},optional={"permanent": bool})
    @classify_admin
    @classify_local
    def changename(self, obdict):
        """ func: change name
            return: success or error
            name: client name
            permanent: permanent or just temporary (cleared when closing client) (default: True) """
        with self.change_name_lock:
            newname = obdict.get("name")
            if check_name(newname) == False:
                return False, "not a valid name"
            #_type = self.links.get("client_server").scn_type
        
            if obdict.get("permanent", True):
                configr = self.links["config_root"]
                oldt = None
                with open(os.path.join(configr,"client_name.txt"), "r") as readn:
                    oldt = readn.read().strip().rstrip().split("/")
                if oldt is None:
                    return False, "reading name failed"
                with open(os.path.join(configr,"client_name.txt"), "w") as writen:
                    if len(oldt) == 2:
                        writen.write("{}/{}".format(newname, oldt[1]))
                    else:
                        writen.write("{}/0".format(newname))

            self.links["client"].name = newname
            self.links["client_server"].name = newname
            self.links["client_server"].update_cache()
            return True
    
    
    @check_argsdeco({"activate": bool})
    @classify_admin
    @classify_local
    def requestredirect(self, obdict):
        """ func: request redirect or deactivate it
            return: success or error
            activate: activate or deactivate redirection"""
        if obdict.get("activate") == True:
            if None in [obdict.get("clientaddress"), obdict.get("clientcert")]:
                return False, "Cannot request redirect when clientaddress and/or hash is not available"
            self.redirect_addr = obdict.get("clientaddress")
            self.redirect_hash = obdict.get("clientcert")
        else:
            self.redirect_addr = ""
            self.redirect_hash = ""
        return True
    
    # TODO: test
    @check_argsdeco({"sourceaddress": str, "sourcehash": str, "entities": list, "hashes": list})
    @classify_experimental
    @classify_admin
    def massimporter(self, obdict):
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
            if self.hashdb.exists(_name) == False:
                self.hashdb.addentity(_name)
            if self.hashdb.exists(_name, _hash) == True:
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
            if _retreferences[0] == True:
                for _ref, _reftype in _retreferences[1]["items"]:
                    if (_ref, _reftype) in localreferences:
                        pass
                    else:
                        self.hashdb.addreference(localref, _ref, _reftype)
                
        return True, "import finished"

