
from common import check_reference, check_reference_type, check_argsdeco, check_name
import os
#logger, isself

from client_config import client_config


class client_admin(object): 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "delservice", "addreference", "updatereference", "delreference", "listplugins"}
    #, "changemsg", "changename"} untested
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    @check_argsdeco({"priority":(int, "priority of client")}) 
    def setpriority(self, obdict):
        """ set priority of client """ 
        if obdict["priority"]<0 or obdict["priority"]>100:
            return False, "out of range"
        
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_prioty()
        return True
        
    #local management
    @check_argsdeco({"name": (str, "entity name")})
    def addentity(self, obdict):
        """ add entity (= named group for hashes) """ 
        return self.hashdb.addentity(obdict["name"])

    @check_argsdeco({"name": (str, "entity name")})
    def delentity(self, obdict):
        """ delete entity """
        return self.hashdb.delentity(obdict["name"])

    @check_argsdeco({"name": (str, "entity name"), "newname": (str, "new entity name")})
    def renameentity(self, obdict):
        """ rename entity """
        return self.hashdb.renameentity(obdict["name"],obdict["newname"])

    @check_argsdeco({"name": (str, "entity"),"hash": (str, "hash of client/server/notimagined yet")},{"type": (str, "type (=client/server/notimagined yet)")}) 
    def addhash(self, obdict):
        """ add hash to entity """
        _type = obdict.get("type")
        _name,  _certhash = obdict["name"], obdict["hash"]
        return self.hashdb.addhash(_name,_certhash,_type)

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success
    #    else:
    #        return (False,error)
    
    @check_argsdeco({"hash": (str, )})
    def delhash(self, obdict):
        """ delete hash """
        return self.hashdb.delhash(obdict["hash"])
    
    
    @check_argsdeco({"hash": (str, ), "security":(str,)})
    def changesecurity(self, obdict):
        """ change security level of hash """
        return self.hashdb.changesecurity(obdict["hash"],obdict["security"])
    
    @check_argsdeco({"hash": (str, ), "newname": (str, )})
    def movehash(self, obdict):
        """ move hash to entity """
        return self.hashdb.movehash(obdict["hash"],obdict["newname"])
    
    # don't expose to other plugins, at least not without question
    # other plugins could check for insecure plugins
    @check_argsdeco()
    def listplugins(self, obdict):
        """ list plugins """
        pluginm = self.links["client_server"].pluginmanager
        out = sorted(pluginm.list_plugins().items())
        ret = []
        for plugin, path in out:
            ret.append((plugin, pluginm.plugin_is_active(plugin)))
        return True, {"items":ret,"map":["plugin","state"]}
    
    @check_argsdeco({"hash": (str, ), "reference": (str, ), "reftype": (str, )})
    def addreference(self, obdict):
        """ add reference to hash """
        _name=self.hashdb.certhash_as_name(obdict["hash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["hash"])
        
        if check_reference(obdict["reference"])==False:
            return False, "reference invalid"
        if check_reference_type(obdict["reftype"])==False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(_name,obdict["hash"])
        return self.hashdb.addreference(_tref[2],obdict["reference"],obdict["reftype"])

    @check_argsdeco({"hash": (str, ), "reference": (str, ), "newreference": (str, ), "newreftype": (str, )})
    def updatereference(self, obdict):
        """ update reference (child of hash) """
        _name=self.hashdb.certhash_as_name(obdict["hash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["hash"])
            
        if check_reference(obdict["newreference"]) == False:
            return False, "reference invalid"
        
        if check_reference_type(obdict["newreftype"]) == False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(_name, obdict["hash"])
        if _tref is None:
            return False,"name, hash not exist"
        
        return self.hashdb.updatereference(_tref[2],obdict["reference"],obdict["newreference"],obdict["newreftype"])

    @check_argsdeco({"hash": (str, "hash"), "reference":(str, "reference")})
    def delreference(self, obdict):
        """ delete reference """
        _name=self.hashdb.certhash_as_name(obdict["hash"])
        
        _tref=self.hashdb.get(_name,obdict["hash"])
        if _tref is None:
            return False, "name, hash not exist"
        return self.hashdb.delreference(_tref[2],obdict["reference"])

    @check_argsdeco({"message": (str, "message")})
    def changemsg(self, obdict):
        """ change message """
        #_type = self.links.get("client_server").scn_type
        configr = self.links["config_root"]
        with open(os.path.join(configr,"client_message.txt"), "w") as wm:
            wm.write(obdict.get("message"))
        return True
    
    @check_argsdeco({"name": (str, "client name")},{"permanent":(bool, "store permanent (default:True)")})
    def changename(self, obdict):
        """ change name """
        newname = obdict.get("name")
        if check_name(newname) == False:
            return False, "not a valid name"
        #_type = self.links.get("client_server").scn_type
        
        
        if obdict.get("permanent", True):
            configr = self.links["config_root"]
            oldt = None
            with open(os.path.join(configr,"client_name.txt"), "r") as readn:
                oldt = readn.read().strip().rstrip().split("/")
            if oldt is None or len(oldt)!=2:
                return False, "reading name failed or length"
            with open(os.path.join(configr,"client_name.txt"), "w") as writen:
                writen.write("{}/{}".format(newname, oldt[1]))
        return True
        
def is_admin_func(funcname):
    if funcname in client_admin.validactions_admin or funcname in client_config.validactions_config:
        return True
    return False
