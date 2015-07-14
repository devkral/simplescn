
import os
from common import logger, isself, success, error, configmanager, check_reference, check_reference_type

class client_admin(object): #"register", 
    validactions_admin = {"addhash", "delhash", "movehash", "addentity", "delentity", "renameentity", "setpriority", "delservice", "setconfig", "setpluginconfig", "addreference","delreference",}
    #, "connect"
    hashdb = None
    links = None
    cert_hash = None
    
    def setpriority(self,*args):
        if len(args)==2:
            _priority,dheader=args
        else:
            return (False,("wrong amount arguments (setpriority): {}".format(args)))
        if type(_priority).__name__=="str" and _priority.isdecimal()==False:
            return (False,"no integer")
        elif type(_priority).__name__=="str":
            _priority=int(_priority)
        elif type(_priority).__name__!="int":
            return (False,"unsupported datatype")
        if _priority<0 or _priority>100:
            return (False,"out of range")
        
        self.links["server"].priority=_priority
        self.links["server"].update_prioty()
        return (True,"priority",isself,self.cert_hash)
        
    #local management
    def addentity(self,_name,dheader):
        temp=self.hashdb.addentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def delentity(self,_name,dheader):
        temp=self.hashdb.delentity(_name)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def renameentity(self,_name,_newname,dheader):
        temp=self.hashdb.renameentity(_name,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)

    def addhash(self,*args):
        if len(args)==3:
            _name, _certhash, dheader=args
            _type=None
        elif len(args)==4:
            _name, _certhash, _type, dheader=args
        else:
            return (False,("wrong amount arguments (addhash): {}".format(args)))
        if self.hashdb.addhash(_name,_certhash,_type) == False:
            return (False,"addhash failed")
        else:
            return (True, success, isself, self.cert_hash)

    #def deljusthash(self,_certhash,dheader):
    #    temp=self.hashdb.delhash(_certhash)
    #    if temp==True:
    #        return (True,success,isself,self.cert_hash)
    #    else:
    #        return (False,error)
        
    def delhash(self,_certhash,dheader):
        temp=self.hashdb.delhash(_certhash)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)
            
    def movehash(self,_certhash,_newname,dheader):
        temp=self.hashdb.movehash(_certhash,_newname)
        if temp==True:
            return (True,success,isself,self.cert_hash)
        else:
            return (False,error)
    def addreference(self,*args):
        if len(args)==5:
            _name,_certhash,_reference,_reftype,dheader=args
        elif len(args)==4:
            _certhash,_reference,_reftype,dheader=args
            _name=self.hashdb.certhash_as_name(_certhash)
            if _name is None:
                return (False,"name not in db")
        else:
            return (False,("wrong amount arguments (addreference): {}".format(args)))
        
        if check_reference(_reference)==False:
            return (False,"reference invalid")
        if check_reference_type(_reftype)==False:
            return (False,"reference type invalid")
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist")
        if self.hashdb.addreference(_tref[2],_reference,_reftype) is None:
            return (False,"adding a reference failed")
        return (True,_reftype,isself,self.cert_hash)
        
    def delreference(self,*args):
        if len(args)==4:
            _name,_certhash,_reference,dheader=args
        elif len(args)==3:
            _certhash,_reference,dheader=args
            _name=self.hashdb.certhash_as_name(_certhash)
            if _name is None:
                return (False,"name not in db")
        else:
            return (False,("wrong amount arguments (delreference): {}".format(args)))
            
        _tref=self.hashdb.get(_name,_certhash)
        if _tref is None:
            return (False,"name,hash not exist")
        if self.hashdb.delreference(_tref[2],_reference) is None:
            return (False,error)
        return (True,success,isself,self.cert_hash)

    def setconfig(self, _key, _value,dheader):
        ret = self.links["configmanager"].set(_key, _value)
        if ret == True:
            return (True, success,isself,self.cert_hash)
        else:
            return (False, error)
    
    def setpluginconfig(self, _plugin, _key, _value, dheader):
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if _plugin not in listplugin:
            return (False, "plugin does not exist")
        if _plugin not in pluginm.plugins:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins",_plugin))
        else:
            config = pluginm.plugins.config
        config.set(_key, _value)
        return (True,success,isself,self.cert_hash)
