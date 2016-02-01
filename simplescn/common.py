
#license: bsd3, see LICENSE.txt
import os, sys
import importlib.machinery
import importlib
import traceback
import threading
import logging
from simplescn import pluginstartfile, check_conftype, check_name, check_hash, check_security, check_typename, check_reference, check_reference_type, default_loglevel
from simplescn import confdb_ending, isself, default_configdir

if hasattr(importlib.util, "module_from_spec") == False:
    import types

class configmanager(object):
    db_path = None
    lock = None
    imported = False
    overlays = {}
    defaults = {"state":("False", bool, "is component active")}
    def __init__(self, _dbpath):
        self.db_path = _dbpath
        self.lock = threading.Lock()
        self.reload()

        
    def __getitem__(self, _name):
        self.get(_name)
    
    def dbaccess(func):
        def funcwrap(self, *args, **kwargs):
            self.lock.acquire()
            if self.db_path is not None:
                import sqlite3
                dbcon = sqlite3.connect(self.db_path)
            else:
                dbcon = None
            temp = None
            try:
                temp = func(self, dbcon, *args, **kwargs)
            except Exception as e:
                if hasattr(e, "__traceback__"):
                    st = "{}\n\n{}".format(e, traceback.format_tb(e.__traceback__))
                else:
                    st = "{}".format(e)
                logging.error(st)
            dbcon.close()
            self.lock.release()
            return temp
        return funcwrap

    @dbaccess
    def reload(self, dbcon):
        if self.db_path is None:
            return
        cur = dbcon.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS main(name TEXT, val TEXT,PRIMARY KEY(name));''')
        # initialise with "False"
        cur.execute('''INSERT OR IGNORE INTO main(name,val) values ("state","False");''')
        dbcon.commit()

    @dbaccess
    def update(self, dbcon, _defaults, _overlays = {}):
        # insert False, don't let it change
        _defaults["state"] = ("False", bool, "is component active")
        self.defaults = {}
        self.overlays = {}
        for _key, elem  in _defaults.items():
            tmp = None
            if len(elem) == 2:
                tmp = [elem[0], elem[1], ""]
            elif len(elem) == 3:
                tmp = list(elem)
            if tmp is None:
                logging.error("invalid default tuple: key:{} tuple:{}".format(_key, elem))
                return False
            if check_conftype(tmp[0], tmp[1]) == False or isinstance(tmp[0], str) == False: # must be string
                return False
            self.defaults[_key] = tmp
        
        for _key, elem  in _overlays.items():
            tmp = None
            if isinstance(elem[0], (str, None)) == False: # must be string
                logging.error("invalid config object {}".format(elem))
                continue
            if len(elem) == 1 or (len(elem) == 2 and elem[1] is None):
                if _key in self.defaults:
                    tmp = self.defaults[_key].copy()
                    tmp[0] = elem[0]
                else:
                    continue
            elif len(elem) == 2:
                tmp = [elem[0], elem[1], ""]
            elif len(elem) == 3:
                tmp = list(elem)
            if tmp is None:
                logging.error("invalid default tuple: key:{} tuple:{}".format(_key, elem))
                return False
            if _key in self.defaults:
                if tmp[1] != self.defaults[_key][1]:
                    logging.error("converter mismatch between defaults: {} and overlays: {}".format(self.defaults[_key][1], tmp[1]))
                    return False

            if check_conftype(tmp[0], tmp[1]) == False:
                return False
            self.overlays[_key] = tmp

        if dbcon is None:
            return True
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM main;''')
        _in_db = cur.fetchall()
        
        for _key, (_value, _type, _doc) in _defaults.items():
            cur.execute('''INSERT OR IGNORE INTO main(name,val) values (?,?);''', (_key, _value))
        if _in_db == None:
            return True
        for elem in _in_db:
            if elem[0] not in _defaults:
                cur.execute('''DELETE FROM main WHERE name=?;''', (elem[0],))
        dbcon.commit()
        return True
        
    @dbaccess
    def set(self, dbcon, name, value):
        if isinstance(name, str) == False:
            logging.error("name not string")
            return False
        if name in self.overlays and check_conftype(value, self.overlays[name][1]) == False:
            #logging.error("overlays value type missmatch")
            return False
        elif name in self.defaults and check_conftype(value, self.defaults[name][1]) == False:
            #logging.error("invalid defaults value type")
            return False
        elif name not in self.defaults and name not in self.overlays:
            logging.error("not in defaults/overlays")
            return False
        
        if value is None:
            value = ""
            
        """if isinstance(value, bool)==True:
            if value==True:
                value="true"
            else:
                value="false" """
        if name in self.overlays or dbcon is None:
            self.overlays[name][0] = str(value)
        elif dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''UPDATE main SET val=? WHERE name=?;''', (str(value), name))
            dbcon.commit()
        return True
    
    def set_default(self, name):
        if name not in self.defaults:
            return False
        return self.set(name, self.defaults[name][0])
    
    # get converted value
    @dbaccess
    def get(self, dbcon, _key):
        """ get converted value """
        if isinstance(_key, str) == False:
            logging.error("key is no string")
            return None
        
        # key can be in overlays but not in defaults
        if _key in self.overlays:
            ret = self.overlays[_key][0]
            _converter = self.overlays[_key][1]
        else:
            if _key not in self.defaults:
                logging.error("\"{}\" is no key".format(_key))
                return None
            _converter = self.defaults[_key][1]
            ret = self.defaults[_key][0]
            if dbcon is not None:
                cur = dbcon.cursor()
                cur.execute('''SELECT val FROM main WHERE name=?;''', (_key,))
                temp = cur.fetchone()
                if temp is not None and temp[0] is not None:
                    ret = temp[0]
                    
        
        if ret is None:
            return ""
        elif ret in ["False", "false", False]:
            return False
        elif ret in ["True", "true", True]:
            return True
        else:
            return _converter(ret)
    
    def getb(self, name):
        """ evaluate value to True/False """
        temp = self.get(name)
        if temp in [None, "-1", -1, "", False]:
            return False
        return True
    
    def get_default(self, name):
        """ return default value as string """
        if name in self.defaults:
            if self.defaults[name] is None:
                return ""
            else:
                return self.defaults[name][0]
        else:
            return None
    
    def get_meta(self, name):
        """ return value with additional information """
        if name in self.overlays:
            return self.overlays[name][1], self.overlays[name][2], False
        elif name in self.defaults:
            return self.defaults[name][1], self.defaults[name][2], True
        else:
            return None
    
    @dbaccess
    def list(self, dbcon, onlypermanent=False):
        ret = []
        _tdic = self.defaults.copy()
        _tdic.update(self.overlays.copy())
        _listitems = sorted(_tdic.items(), key=lambda t: t[0])
        if dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''SELECT name, val FROM main;''')
            _in_db_list = cur.fetchall()
            _in_db = {}
            
            if _in_db_list is not None:
                for _key, _val in _in_db_list:
                    _in_db[_key] = _val
        
        for elem in _listitems:
            if len(elem) != 2 or len(elem[1]) != 3:
                logging.error("invalid element {}".format(elem))
                continue
            _key, (_defaultval, _converter, _doc) = elem
            _val2 = _defaultval
            ispermanent = True
            # ignore overlayentries with entry None
            if _key in self.overlays: # and self.overlays[_key] is not None:
                _val2 = self.overlays[_key][0]
                _converter, _doc = self.overlays[_key][1:]
                ispermanent = False
            elif _key in _in_db:
                _val2 = _in_db[_key]
                ispermanent = True
            if _val2 is None:
                _val2 = ""
            
            if _val2 in ["False", "false", False]:
                _val2 = "False"
            elif _val2 in ["True", "true", True]:
                _val2 = "True"
            else:
                if _converter is bool:
                    _val2 = bool(_val2)
                _val2 = str(_val2)
            if _key in ["state",] and _val2 in [None, "", "False"]:
                _val2 = "False"
            if isinstance(_val2, str) == False:
                logging.info("value should be str")
                
            if onlypermanent == True and ispermanent == True:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
            elif onlypermanent == False:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
        return ret

def pluginresources_creater(_dict, requester):
    if requester == "":
        return None #crash instead
    def wrap(res):
        ob = _dict.get(res)
        if ob is None:
            logging.error("Resource: {} not available".format(res))
            return None
        elif callable(ob) == True:
            def wrap2(*args, **kwargs):
                kwargs["requester"] = requester
                return ob(*args,**kwargs)
            return wrap2
        #elif hasattr(ob, "shared_with") and 
        else:
            return ob.copy()
    return wrap


class pluginmanager(object):
    pluginenv = None
    pathes_plugins = None
    path_plugins_config = None
    resources = None
    interfaces = []
    plugins = {}
    
    def __init__(self, _pathes_plugins, _path_plugins_config, scn_type, resources = {}, pluginenv = {}):
        self.pluginenv = pluginenv
        self.pathes_plugins = _pathes_plugins
        self.path_plugins_config = _path_plugins_config
        self.pluginenv = pluginenv
        self.resources = resources
        self.interfaces.insert(0, scn_type)
        if hasattr(importlib.util, "module_from_spec"):
            module = importlib.machinery.ModuleSpec("_plugins", None)
            module = importlib.util.module_from_spec(module)
        else:
            module = types.ModuleType("_plugins", None)
        sys.modules[module.__name__] = module
        
        
    def list_plugins(self):
        temp = {}
        for path in self.pathes_plugins:
            if os.path.isdir(path) == True:
                for plugin in os.listdir(path):
                    if plugin in ["__pycache__", ""] or plugin[0] in " \t\b" or plugin[-1] in " \t\b":
                        continue
                    newpath = os.path.join(path, plugin)
                    if os.path.isdir(newpath) == True and os.path.isfile(os.path.join(newpath, pluginstartfile)) == True and plugin not in temp:
                        temp[plugin] = path
        return temp
    
    def plugin_is_active(self, plugin):
        pconf = configmanager(os.path.join(self.path_plugins_config,"{}{}".format(plugin, confdb_ending)))
        return pconf.getb("state")
             
    
    def clean_plugin_config(self):
        lplugins = self.list_plugins()
        lconfig = os.listdir(self.path_plugins_config)
        for dbconf in lconfig:
            #remove .confdb
            if dbconf[:-len(confdb_ending)] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config, dbconf))
    
    def load_pluginconfig(self, plugin):
        if plugin in self.plugins:
            return self.plugins[plugin].config
        plugins = self.list_plugins()
        pluginpath = plugins.get(plugin)
        if pluginpath is None:
            return None
        plugin = (plugin, pluginpath)
        pconf = configmanager(os.path.join(self.path_plugins_config,"{}{}".format(plugin[0], confdb_ending)))
        
            
        if hasattr(importlib.util, "module_from_spec"):
            module = importlib.machinery.ModuleSpec("_plugins.{}".format(plugin[0]), None, origin=plugin[1])
            module.submodule_search_locations = [os.path.join(plugin[1],plugin[0]), plugin[1]]
            module = importlib.util.module_from_spec(module)
        else:
            module = types.ModuleType("_plugins.{}".format(plugin[0]), None)
            module.__path__ = [os.path.join(plugin[1],plugin[0]), plugin[1]]
            
            
        sys.modules[module.__name__] = module
        #print(sys.modules.get("plugins"),sys.modules.get("plugins.{}".format(plugin[0])))
        globalret = self.pluginenv.copy()
        globalret["__name__"] = "_plugins.{}.{}".format(plugin[0], pluginstartfile.rsplit(".",1)[0])
        globalret["__package__"] = "_plugins.{}".format(plugin[0])
        globalret["__file__"] = os.path.join(plugin[1], plugin[0], pluginstartfile)
        try:
            with open(os.path.join(plugin[1], plugin[0], pluginstartfile), "r") as readob:
                exec(readob.read(), globalret)
                # unchangeable default, check that config_defaults is really a dict
            if isinstance(globalret.get("config_defaults", None), dict) == False or issubclass(dict, type(globalret["config_defaults"])) == False:
                    logging.error("global value: config_defaults is no dict/not specified")
                    return None
            globalret["config_defaults"]["state"] = ("False", bool, "is plugin active")
            pconf.update(globalret["config_defaults"])
        except Exception as e:
            st = "Plugin failed to load, reason:\n{}".format(e)
            if hasattr(e,"tb_frame"):
                st += "\n\n{}".format(traceback.format_tb(e))
            logging.error(st)
        # delete namespace stub
        del sys.modules[module.__name__]
        return pconf
    
    def init_plugins(self):
        lplugins = self.list_plugins()
        for plugin in lplugins.items():
            pconf = configmanager(os.path.join(self.path_plugins_config,"{}{}".format(plugin[0], confdb_ending)))
            if pconf.getb("state") == False:
                continue
                
            
            if hasattr(importlib.util, "module_from_spec"):
                module = importlib.machinery.ModuleSpec("_plugins.{}".format(plugin[0]), None, origin=plugin[1])
                module.submodule_search_locations = [os.path.join(plugin[1],plugin[0]), plugin[1]]
                module = importlib.util.module_from_spec(module)
            else:
                module = types.ModuleType("_plugins.{}".format(plugin[0]), None)
                module.__path__ = [os.path.join(plugin[1],plugin[0]), plugin[1]]
            
                
            sys.modules[module.__name__] = module
            #print(sys.modules.get("plugins"),sys.modules.get("plugins.{}".format(plugin[0])))
            globalret = self.pluginenv.copy()
            globalret["__name__"] = "_plugins.{}.{}".format(plugin[0], pluginstartfile.rsplit(".",1)[0])
            globalret["__package__"] = "_plugins.{}".format(plugin[0])
            globalret["__file__"] = os.path.join(plugin[1], plugin[0], pluginstartfile)
            finobj = None
            try:
                with open(os.path.join(plugin[1], plugin[0], pluginstartfile), "r") as readob:
                    exec(readob.read(), globalret)
                    # unchangeable default, check that config_defaults is really a dict
                    if isinstance(globalret.get("config_defaults", None), dict) == False or issubclass(dict, type(globalret["config_defaults"])) == False:
                        logging.error("global value: config_defaults is no dict/not specified")
                        continue
                    globalret["config_defaults"]["state"] = ("False", bool, "is plugin active")
                    pconf.update(globalret["config_defaults"])
                    finobj = globalret["init"](self.interfaces.copy(), pconf, pluginresources_creater(self.resources, plugin[0]), os.path.join(plugin[1], plugin[0]))
            except Exception as e:
                st = "Plugin failed to load, reason:\n{}".format(e)
                if hasattr(e,"tb_frame"):
                    st += "\n\n{}".format(traceback.format_tb(e))
                logging.error(st)

                finobj = None
            if finobj:
                # config is found in finobj.config
                self.plugins[plugin[0]] = finobj
            else:
                # delete namespace stub
                del sys.modules[module.__name__]

    def register_remote(self, _addr):
        self.redirect_addr = _addr

    def delete_remote(self):
        self.redirect_addr = ""


class certhash_db(object):
    db_path = None
    lock = None

    def __init__(self,dbpath):
        import sqlite3
        self.db_path = dbpath
        self.lock = threading.Lock()
        try:
            con = sqlite3.connect(self.db_path)
        except Exception as e:
            logging.error(e)
            return
        self.lock.acquire()
        try:
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, security TEXT, certreferenceid INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
            con.execute('''CREATE TABLE if not exists certreferences(certreferenceid INTEGER, certreference TEXT, type TEXT, PRIMARY KEY(certreferenceid,certreference), FOREIGN KEY(certreferenceid) REFERENCES certs(certreferenceid) ON DELETE CASCADE);''')
            #hack:
            con.execute('''CREATE TABLE if not exists certrefcount(certreferenceid INTEGER);''')
            con.execute('''INSERT INTO certrefcount(certreferenceid) values(?);''', (0,))
            con.commit()
        except Exception as e:
            con.rollback()
            logging.error(e)
        con.close()
        self.lock.release()

    def connecttodb(func):
        import sqlite3
        def funcwrap(self, *args, **kwargs):
            temp = None
            self.lock.acquire()
            try:
                dbcon = sqlite3.connect(self.db_path)
                temp = func(self, dbcon, *args, **kwargs)
                dbcon.close()
            except Exception as e:
                st = str(e)
                if "tb_frame" in e.__dict__:
                    st = "{}\n\n{}".format(st, traceback.format_tb(e))
                logging.error("{}\n{}".format(st, type(func).__name__))
            self.lock.release()
            return temp
        return funcwrap

    @connecttodb
    def addentity(self, dbcon, _name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''',(_name,))
        if cur.fetchone() is not None:
            logging.info("name exist: {}".format(_name))
            return False
        if check_name(_name) == False:
            logging.info("name contains invalid elements")
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values (?,'default');''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delentity(self,dbcon,_name):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            #logging.info("name does not exist: {}".format(_name))
            return True
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def renameentity(self, dbcon, _name, _newname):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logging.info("name does not exist: {}".format(_name))
            return False
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is not None:
            logging.info("newname already exist: {}".format(_newname))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE name=?;''', (_newname, _name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self, dbcon, _name, _certhash, nodetype="unknown", priority=20, security="valid"):
        if _name is None:
            logging.error("name None")
        if nodetype is None:
            logging.error("nodetype None")
        
        if check_hash(_certhash) == False:
            logging.error("hash contains invalid characters: {}".format(_certhash))
            return False
        
        if check_security(security) == False:
            logging.error("security is invalid type: {}".format(security))
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logging.info("name does not exist: {}".format(_name))
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname=cur.fetchone()
        if _oldname is not None:
            logging.info("hash already exist: {}".format(_certhash))
            return False

        #hack
        cur.execute('''SELECT certreferenceid FROM certrefcount''')
        count = cur.fetchone()[0]
        cur.execute('''UPDATE certrefcount SET certreferenceid=?''', (count+1,))
        #hack end
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,security,certreferenceid) values(?,?,?,?,?,?);''', (_name, _certhash, nodetype, priority, security, count))

        dbcon.commit()
        return True

    @connecttodb
    def movehash(self,dbcon,_certhash,_newname):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is None:
            logging.info("name does not exist: {}".format(_newname))
            return False

        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname = cur.fetchone()
        if _oldname is None:
            logging.info("certhash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET name=? WHERE certhash=?;''', (_newname, _certhash,))

        dbcon.commit()
        return True

    @connecttodb
    def changetype(self, dbcon, _certhash, _type):
        if check_typename(_type,15) == False:
            logging.info("type contains invalid characters or is too long (maxlen: {}): {}".format(15, _type))
            return False
        if check_hash(_certhash) == False:
            logging.info("hash contains invalid characters")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: {}".format(_certhash))
            return False
        cur.execute('''UPDATE certs SET type=? WHERE certhash=?;''', (_type, _certhash))

        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self, dbcon, _certhash, _priority):
        #convert str to int and fail if either no integer in string format
        # or datatype is something else except int
        if isinstance(_priority, str) == True and _priority.isdecimal() == False:
            logging.info("priority can not parsed as integer: {}".format(_priority))
            return False
        elif isinstance(_priority, str) == True:
            _priority=int(_priority)
        elif isinstance(_priority, int) == False:
            logging.info("priority has unsupported datatype: {}".format(type(_priority).__name__))
            return False

        if _priority < 0 or _priority > 100:
            logging.info("priority too big (>100) or smaller 0")
            return False
        
        if check_hash(_certhash) == False:
            logging.info("hash contains invalid characters: {}".format(_certhash))
            return False
        cur = dbcon.cursor()
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: {}".format(_certhash))
            return False

        cur.execute('''UPDATE certs SET priority=? WHERE certhash=?;''', (_priority, _certhash))

        dbcon.commit()
        return True
    
    @connecttodb
    def changesecurity(self, dbcon, _certhash, _security):
        if check_hash(_certhash) == False:
            logging.info("hash contains invalid characters: {}".format(_certhash))
            return False
        if check_security(_security) == False:
            logging.error("security is invalid type: {}".format(_security))
            return False
            
        cur = dbcon.cursor()
        
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: {}".format(_certhash))
            return False

        cur.execute('''UPDATE certs SET security=? WHERE certhash=?;''', (_security, _certhash))

        dbcon.commit()
        return True
    
    def updatehash(self, _certhash, certtype=None, priority=None, security=None):
        if certtype is not None:
            if self.changetype(_certhash, certtype) == False:
                return False
        if priority is not None:
            if self.changepriority(_certhash, priority) == False:
                return False
        if certtype is not None:
            if self.changesecurity(_certhash, security) == False:
                return False
        
    
    @connecttodb
    def delhash(self, dbcon, _certhash):
        if _certhash == "default":
            logging.error("tried to delete reserved hash 'default'")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''',(_certhash,))

        if cur.fetchone() is None:
            #logging.info("hash does not exist: {}".format(_certhash))
            return True

        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (_certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def get(self, dbcon, _certhash):
        if _certhash is None:
            return None
        if check_hash(_certhash) == False:
            logging.error("Invalid certhash: {}".format(_certhash))
            return None
        cur = dbcon.cursor()
        cur.execute('''SELECT name,type,priority,security,certreferenceid FROM certs WHERE certhash=?;''', (_certhash,))
        ret = cur.fetchone()
        if ret is not None and ret[0] == isself:
            logging.critical("\"{}\" is in the db".format(isself))
            return None
        return ret
    
    @connecttodb
    def listhashes(self, dbcon, _name, _nodetype = None):
        #if check_name(_name) == False:
        #    return None
        
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' ORDER BY priority DESC;''', (_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' AND type=? ORDER BY priority DESC;''', (_name, _nodetype))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    

    @connecttodb
    def listnodenames(self, dbcon, _nodetype = None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT DISTINCT name FROM certs ORDER BY name ASC;''')
        else:
            cur.execute('''SELECT DISTINCT name FROM certs WHERE type=? ORDER BY name ASC;''',(_nodetype,))
        out = cur.fetchall()
        if out is None:
            return None
        else:
            return [elem[0] for elem in out]
    
    @connecttodb
    def listnodenametypes(self, dbcon):
        cur = dbcon.cursor()
        cur.execute('''SELECT DISTINCT name,type FROM certs ORDER BY name ASC;''')
        out = cur.fetchall()
        if out is None:
            return None
        else:
            return out
    
    @connecttodb
    def listnodeall(self, dbcon, _nodetype = None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs ORDER BY priority DESC;''')
        else:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs ORDER BY priority WHERE type=? DESC;''', (_nodetype,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    
    #@connecttodb
    def certhash_as_name(self, _certhash):
        ret = self.get(_certhash)
        if ret is None:
            return None
        else:
            return ret[0]
    
    @connecttodb
    def exist(self, dbcon, _name, _hash = None):
        cur = dbcon.cursor()
        if _hash is None:
            cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        else:
            cur.execute('''SELECT name FROM certs WHERE name=? AND certhash=?;''', (_name, _hash))
        if cur.fetchone() is None:
            return False
        else:
            return True
    
    @connecttodb
    def addreference(self, dbcon, _referenceid, _reference, _reftype):
        if check_reference(_reference) == False:
            logging.error("reference invalid: {}".format(_reference))
            return False
        if check_reference_type(_reftype) == False:
            logging.error("reference type invalid: {}".format(_reftype))
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_referenceid, _reference))
        if cur.fetchone() is not None:
            logging.info("certreferenceid exist: {}".format(_referenceid))
            return False
        cur.execute('''INSERT INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (_referenceid, _reference, _reftype))
        dbcon.commit()
        return True
    
    @connecttodb
    def delreference(self, dbcon, _certreferenceid, _reference):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            #logging.info("certreferenceid/reference does not exist: {}, {}".format(_certreferenceid, _reference))
            return True
        cur.execute('''DELETE FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def updatereference(self, dbcon, _certreferenceid, _reference, _newreference, _newreftype):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            logging.info("certreferenceid/reference does not exist:{}, {}".format(_certreferenceid, _reference))
            return False
        if _reference != _newreference:
            cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _newreference))
            if cur.fetchone() is not None:
                logging.info("new reference does exist: {}, {}".format(_certreferenceid, _reference))
                return False
        if _reference != _newreference:
            cur.execute('''UPDATE certreferences SET certreference=?, type=? WHERE certreferenceid=? and certreference=?;''', (_newreference, _newreftype, _certreferenceid, _reference))
        else:
            cur.execute('''UPDATE certreferences SET type=? WHERE certreferenceid=? and certreference=?;''', (_newreftype, _certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def getreferences(self, dbcon, _referenceid, _reftype = None):
        if isinstance(_referenceid, int) == False:
            logging.error("invalid referenceid")
            return None
        cur = dbcon.cursor()
        if _reftype is None:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=?;''', (_referenceid,))
        else:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=? and type=?;''', (_referenceid, _reftype))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out
    
    
    @connecttodb
    def movereferences(self,dbcon,_oldrefid,_newrefid):
        cur = dbcon.cursor()
        
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_oldrefid,))
        if cur.fetchone() is None:
            logging.info("src certrefid does not exist: {}".format(_oldrefid))
            return False
            
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_newrefid,))
        if cur.fetchone() is None:
            logging.info("dest certrefid does not exist: {}".format(_newrefid))
            return False

        cur.execute('''UPDATE certreferences SET certreferenceid=? WHERE certreferenceid=?;''', (_newrefid, _oldrefid))

        dbcon.commit()
        return True
        
    #@connecttodb
    #def listreferences(self, dbcon, _reftype = None):
    #    cur = dbcon.cursor()
    #    cur.execute('''SELECT DISTINCT name,type FROM certreferences WHERE type ORDER BY name ASC;''',(_reftype, ))
    #    return cur.fetchall()
    
    @connecttodb
    def findbyref(self, dbcon, _reference):
        if check_reference(_reference) == False:
            logging.error("invalid reference")
            return None
        cur = dbcon.cursor()
        cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs WHERE certreferenceid IN (SELECT DISTINCT certreferenceid FROM certreferences WHERE certreference=?);''', (_reference,))
        out = cur.fetchall()
        if out is None:
            return []
        else:
            return out



# default_args, overwrite_args are modified
def scnparse_args(_funchelp, default_args={}, overwrite_args={}):
    pluginpathes = []
    if len(sys.argv) > 1:
        tparam = ()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help","h"]:
                print(_funchelp())
                sys.exit(0)
            else:
                tparam = elem.split("=")
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    tparam = [tparam[0], "True"]
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1], ]
                    continue
                # autoconvert name to loglevel
                if tparam[0] == "loglevel":
                    tparam[1] = str(loglevel_converter(tparam[1]))
                    logging.root.setLevel(int(tparam[1]))
                if tparam[0] in overwrite_args:
                    overwrite_args[tparam[0]][0] = tparam[1]
                elif tparam[0] in default_args: # are overwritten without changing default
                    overwrite_args[tparam[0]] = default_args[tparam[0]].copy()
                    overwrite_args[tparam[0]][0] = tparam[1]
    return pluginpathes
    
    
    

overwrite_plugin_config_args={"config": [default_configdir, str, "<dir>: path to config dir"],
             "plugin": ["", str, "<name>: Plugin name"],
             "key": ["", str, "<name>: config key"],
             "value": ["", str, "<name>: config value"]}

def plugin_config_paramhelp():
    t = "# parameters (non-permanent)\n"
    for _key, elem in sorted(overwrite_plugin_config_args.items(), key=lambda x: x[0]):
        t += "  * {}: {}: {}\n".format(_key, elem[0], elem[2])
    return t
