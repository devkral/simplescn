
import os
from common import logger, isself, success, error, configmanager, check_reference, check_reference_type

class client_admin(object): #"register", 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "delservice", "setconfig", "setpluginconfig", "addreference", "updatereference", "delreference",}
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    def setpriority(self, _priority):
        if type(_priority).__name__=="str" and _priority.isdecimal()==False:
            return (False,"no integer",isself,self.cert_hash)
        elif type(_priority).__name__=="str":
            _priority=int(_priority)
        elif type(_priority).__name__!="int":
            return (False,"unsupported datatype",isself,self.cert_hash)
        if _priority<0 or _priority>100:
            return (False,"out of range",isself,self.cert_hash)
        
        self.links["server"].priority=_priority
        self.links["server"].update_prioty()
        return (True,"priority",isself,self.cert_hash)
        
    #local management
    def addentity(self,_name):
        temp=self.hashdb.addentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error,isself,self.cert_hash)

    def delentity(self,_name):
        temp=self.hashdb.delentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error,isself,self.cert_hash)

    def renameentity(self, _name, _newname):
        temp=self.hashdb.renameentity(_name,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error,isself,self.cert_hash)

    def addhash(self,*args):
        if len(args)==2:
            _name, _certhash=args
            _type=None
        elif len(args)==3:
            _name, _certhash, _type=args
        else:
            return (False,"wrong amount arguments (addhash): {}".format(args),isself,self.cert_hash)
        if self.hashdb.addhash(_name,_certhash,_type) == False:
            return (False,"addhash failed",isself,self.cert_hash)
        else:
            return (True, success, isself, self.cert_hash)

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success,isself,self.cert_hash)
    #    else:
    #        return (False,error)
        
    def delhash(self,_certhash):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error,isself,self.cert_hash)
            
    def movehash(self,_certhash,_newname):
        temp=self.hashdb.movehash(_certhash,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error,isself,self.cert_hash)
    
    def addreference(self, _certhash,_reference,_reftype):
        _name=self.hashdb.certhash_as_name(_certhash)
        if _name is None:
            return (False,"hash not in db: {}".format(_certhash),isself,self.cert_hash)
        
        if check_reference(_reference)==False:
            return (False,"reference invalid",isself,self.cert_hash)
        if check_reference_type(_reftype)==False:
            return (False,"reference type invalid",isself,self.cert_hash)
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist",isself,self.cert_hash)
        if self.hashdb.addreference(_tref[2],_reference,_reftype) is None:
            return (False,"adding a reference failed",isself,self.cert_hash)
        return (True,"reference added",isself,self.cert_hash)
    
    def updatereference(self, _certhash, _reference, _newreference, _newreftype):
        _name=self.hashdb.certhash_as_name(_certhash)
        if _name is None:
            return (False,"hash not in db: {}".format(_certhash),isself,self.cert_hash)
            
        if check_reference(_newreference) == False:
            return (False, "reference invalid", isself, self.cert_hash)
        
        if check_reference_type(_newreftype) == False:
            return (False, "reference type invalid", isself, self.cert_hash)
            
        _tref=self.hashdb.get(_name, _certhash)
        if _tref is None:
            return (False,"name, hash not exist", isself, self.cert_hash)
        
        if self.hashdb.updatereference(_tref[2],_reference,_newreference,_newreftype) is None:
            return (False,"updating reference failed",isself,self.cert_hash)
        return (True,"reference updated",isself,self.cert_hash)

    
    def delreference(self,*args):
        if len(args)==3:
            _name, _certhash, _reference=args
        elif len(args)==2:
            _certhash,_reference=args
            _name=self.hashdb.certhash_as_name(_certhash)
            if _name is None:
                return (False,"name not in db",isself,self.cert_hash)
        else:
            return (False,"wrong amount arguments (delreference): {}".format(args),isself,self.cert_hash)
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist",isself,self.cert_hash)
        if self.hashdb.delreference(_tref[2],_reference) is None:
            return (False,error,isself,self.cert_hash,isself,self.cert_hash)
        return (True,"reference deleted",isself,self.cert_hash)

    def setconfig(self, _key, _value):
        ret = self.links["configmanager"].set(_key, _value)
        if ret == True:
            return (True, "mainconfig: key set",isself,self.cert_hash)
        else:
            return (False, "mainconfig: setting key failed",isself,self.cert_hash)
    
    def setpluginconfig(self, _plugin, _key, _value):
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if _plugin not in listplugin:
            return (False, "plugin does not exist",isself,self.cert_hash)
        if _plugin not in pluginm.plugins:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins",_plugin))
        else:
            config = pluginm.plugins.config
        config.set(_key, _value)
        return (True,success,isself,self.cert_hash)

