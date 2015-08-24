
import os
from common import logger, isself, configmanager, check_reference, check_reference_type, confdb_ending, check_args, gen_result, generate_error

class client_admin(object): #"register", 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "delservice", "addreference", "updatereference", "delreference", "set_config", "set_pluginconfig", "clean_pluginconfig", "reset_configkey", "reset_pluginconfigkey"}
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    def setpriority(self, obdict):
        if check_args(obdict, (("priority",int),)) == False:
            return False, "check_args failed (setpriority)"
        if obdict["priority"]<0 or obdict["priority"]>100:
            return gen_result([generate_error("out of range")], False)
        
        self.links["server"].priority = obdict["priority"]
        self.links["server"].update_prioty()
        return True, "success"
        
    #local management
    def addentity(self, obdict):
        if check_args(obdict, (("name",str),)) == False:
            return False, "check_args failed (addentity)"
        temp=self.hashdb.addentity(obdict["name"])
        if temp==True:
            return True, "success"
        else:
            return False, "error"

    def delentity(self, obdict):
        if check_args(obdict, (("name",str),)) == False:
            return False, "check_args failed (delentity)"
        temp=self.hashdb.delentity(obdict["name"])
        if temp==True:
            return True, "success"
        else:
            return False, "error"

    def renameentity(self, obdict):
        if check_args(obdict, (("name",str),("newname",str))) == False:
            return False, "check_args failed (renameentity)"
        temp=self.hashdb.renameentity(obdict["name"],obdict["newname"])
        if temp==True:
            return True, "success"
        else:
            return False, "error"

    def addhash(self,obdict):
        if check_args(obdict, (("name",str),("certhash",str),("type",str))) == False:
            _name, _certhash, _type = obdict["name"], obdict["certhash"], obdict["type"]
        elif check_args(obdict, (("name",str),("certhash",str))) == False:
            _certhash, _type = obdict["name"], obdict["certhash"]
        else:
            return False, "check_args failed (addhash)"
        if self.hashdb.addhash(_name,_certhash,_type) == False:
            return False,"addhash failed"
        else:
            return True, "success"

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success
    #    else:
    #        return (False,error)
        
    def delhash(self, obdict):
        if check_args(obdict, (("certhash",str),)) == False:
            return False, "check_args failed (delhash)"
        temp=self.hashdb.delhash(obdict["certhash"])
        if temp==True:
            return True, "success"
        else:
            return False, "error"
            
    def movehash(self, obdict):
        if check_args(obdict, (("certhash",str),("newname",str))) == False:
            return False, "check_args failed (movehash)"
        #_certhash,_newname):
        temp=self.hashdb.movehash(obdict["certhash"],obdict["newname"])
        if temp==True:
            return True, "success"
        else:
            return "False", "error"
    
    def addreference(self, obdict):
        if check_args(obdict, (("certhash",str),("reference",str),("reftype",str))) == False:
            return False, "check_args failed (addreference)"
        _name=self.hashdb.certhash_as_name(obdict["certhash"])
        if _name is None:
            return False,"hash not in db: {}".format(obdict["certhash"])
        
        if check_reference(obdict["reference"])==False:
            return False, "reference invalid"
        if check_reference_type(obdict["reftype"])==False:
            return False, "reference type invalid"
            
        _tref=self.hashdb.get(_name,obdict["certhash"])
        if self.hashdb.addreference(_tref[2],obdict["reference"],obdict["reftype"]) is None:
            return False, "adding a reference failed"
        return True,"reference added"
    
    def updatereference(self, obdict): # _certhash, _reference, _newreference, _newreftype):
        if check_args(obdict, (("certhash",str),("reference",str),("newreference",str),("newreftype",str))) == False:
            return False, "check_args failed (updatereference)"
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
        
        if self.hashdb.updatereference(_tref[2],obdict["reference"],obdict["newreference"],obdict["newreftype"]) is None:
            return False, "updating reference failed"
        return True, "reference updated"

    
    def delreference(self, obdict):
        if check_args(obdict, (("certhash",str),("reference",str))) == False:
            return False, "check_args failed (delreference)"
        _name=self.hashdb.certhash_as_name(obdict["certhash"])
        
        _tref=self.hashdb.get(_name,obdict["certhash"])
        if _tref is None:
            return False,"name,hash not exist"
        if self.hashdb.delreference(_tref[2],obdict["reference"]) is None:
            return False, "error"
        return True,"reference deleted"

    def set_config(self, obdict):
        if check_args(obdict, (("key",str),("value",str))) == False:
            return False, "check_args failed (set_config)"
        ret = self.links["configmanager"].set(obdict["key"], obdict["value"])
        if ret == True:
            return True, "mainconfig: key set"
        else:
            return False, "mainconfig: setting key failed"
    
    def set_pluginconfig(self, obdict):
        if check_args(obdict, (("plugin",str),("key",str),("value",str))) == False:
            return False, "check_args failed (set_pluginconfig)"
        
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or "config" not in pluginm.plugins[obdict["plugin"]].__dict__:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        ret = config.set(obdict["key"], obdict["value"])
        if ret == True:
            return True, "pluginconfig: key set"
        else:
            return False, "pluginconfig: setting key failed"
    
    def reset_configkey(self, obdict):
        if check_args(obdict, (("key",str),)) == False:
            return False, "check_args failed (reset_configkey)"
        ret = self.links["configmanager"].set_default(obdict["key"])
        if ret == True:
            return True, "mainconfig: key resetted"
        else:
            return False, "mainconfig: resetting key failed"
    
    def reset_pluginconfigkey(self, obdict): #_plugin, _key):
        if check_args(obdict, (("plugin",str),("key",str))) == False:
            return False, "check_args failed (reset_configkey)"
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or "config" not in pluginm.plugins[obdict["plugin"]].__dict__:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        ret = config.set_default(obdict["key"])
        if ret == True:
            return True, "pluginconfig: key resetted"
        else:
            return False, "pluginconfig: resetting key failed"
    
    def clean_pluginconfig(self, obdict):
        pluginm=self.links["client_server"].pluginmanager
        pluginm.clean_plugin_config()
        return True, "pluginconfig cleaned up"
        
        

