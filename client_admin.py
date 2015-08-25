
import os
from common import configmanager, check_reference, check_reference_type, confdb_ending, check_argsdeco
#logger, isself

class client_admin(object): #"register", 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "delservice", "addreference", "updatereference", "delreference", "set_config", "set_pluginconfig", "clean_pluginconfig", "reset_configkey", "reset_pluginconfigkey"}
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    @check_argsdeco((("priority",int),)) 
    def setpriority(self, obdict):
        if obdict["priority"]<0 or obdict["priority"]>100:
            return False, "out of range"
        
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_prioty()
        return True
        
    #local management
    @check_argsdeco((("name",str),)) 
    def addentity(self, obdict):
        return self.hashdb.addentity(obdict["name"])

    @check_argsdeco((("name",str),)) 
    def delentity(self, obdict):
        return self.hashdb.delentity(obdict["name"])

    @check_argsdeco((("name",str),("newname", str))) 
    def renameentity(self, obdict):
        return self.hashdb.renameentity(obdict["name"],obdict["newname"])

    @check_argsdeco((("name",str),("hash", str)), (("type", str))) 
    def addhash(self, obdict):
        _type = obdict.get("type")
        _name,  _certhash = obdict["name"], obdict["hash"]
        return self.hashdb.addhash(_name,_certhash,_type)

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success
    #    else:
    #        return (False,error)
    
    @check_argsdeco((("hash", str), ))
    def delhash(self, obdict):
        return self.hashdb.delhash(obdict["hash"])
    
    @check_argsdeco((("hash", str), ("newname", str)))
    def movehash(self, obdict):
        return self.hashdb.movehash(obdict["certhash"],obdict["newname"])
    
    @check_argsdeco((("hash", str), ("reference", str), ("reftype", str)))
    def addreference(self, obdict):
        _name=self.hashdb.certhash_as_name(obdict["certhash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["certhash"])
        
        if check_reference(obdict["reference"])==False:
            return False, "reference invalid"
        if check_reference_type(obdict["reftype"])==False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(_name,obdict["certhash"])
        return self.hashdb.addreference(_tref[2],obdict["reference"],obdict["reftype"])

    @check_argsdeco((("hash", str), ("reference", str), ("newreference", str), ("newreftype", str)))
    def updatereference(self, obdict):
        _name=self.hashdb.certhash_as_name(obdict["certhash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["certhash"])
            
        if check_reference(obdict["newreference"]) == False:
            return False, "reference invalid"
        
        if check_reference_type(obdict["newreftype"]) == False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(_name, obdict["certhash"])
        if _tref is None:
            return False,"name, hash not exist"
        
        return self.hashdb.updatereference(_tref[2],obdict["reference"],obdict["newreference"],obdict["newreftype"])

    @check_argsdeco((("hash", str), ("reference", str)))
    def delreference(self, obdict):
        _name=self.hashdb.certhash_as_name(obdict["certhash"])
        
        _tref=self.hashdb.get(_name,obdict["certhash"])
        if _tref is None:
            return False, "name, hash not exist"
        return self.hashdb.delreference(_tref[2],obdict["reference"])

    @check_argsdeco((("key", str), ("value", str)))
    def set_config(self, obdict):
        return self.links["configmanager"].set(obdict["key"], obdict["value"])

    @check_argsdeco((("key", str), ("value", str), ("plugin", str)))
    def set_pluginconfig(self, obdict):        
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or "config" not in pluginm.plugins[obdict["plugin"]].__dict__:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return config.set(obdict["key"], obdict["value"])

    @check_argsdeco((("key", str),))
    def reset_configkey(self, obdict):
        return self.links["configmanager"].set_default(obdict["key"])

    @check_argsdeco((("key", str), ("plugin", str)))
    def reset_pluginconfigkey(self, obdict):
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or "config" not in pluginm.plugins[obdict["plugin"]].__dict__:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return config.set_default(obdict["key"])
        
    
    @check_argsdeco()
    def clean_pluginconfig(self, obdict):
        pluginm=self.links["client_server"].pluginmanager
        pluginm.clean_plugin_config()
        return True
        
        

