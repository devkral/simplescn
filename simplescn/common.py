
#license: bsd3, see LICENSE.txt
import os
import sys
import importlib.machinery
import importlib
import traceback
import threading
import logging
import json


if not hasattr(importlib.util, "module_from_spec"):
    import types

try:
    import markdown
except ImportError:
    pass


from simplescn import pluginstartfile, pluginconfigdefaults, check_conftype, check_name, check_hash, check_security, check_typename, check_reference, check_reference_type
from simplescn import confdb_ending, isself, default_configdir, loglevel_converter, max_typelength


def verify_config(obj):
    if not isinstance(obj, dict):
        return False
    for name, value in obj.items():
        if not isinstance(name, str):
            return False
        if not isinstance(value, (list, tuple)) or len(value) != 3:
            return False
        if not isinstance(value[0], str) or not isinstance(value[2], str):
            return False
        if not callable(value[1]):
            return False
    return True

convertmap = \
{
    "json": json.loads,
    "str": str,
    "int": int,
    "float": float,
    "path": lambda p:os.path.expanduser(os.path.expandvars(p))
}

# no return needed, references
def convert_config(obj):
    for name, value in obj.items():
        if not callable(value[1]):
            value[1] = convertmap.get(value[1], str)


class configmanager(object):
    db_path = None
    lock = None
    imported = False
    overlays = None
    defaults = None
    def __init__(self, _dbpath):
        # init here because of multiple instances
        self.overlays = {}
        # unchangeable default
        self.defaults = {"state":("False", bool, "is component active")}
        self.db_path = _dbpath
        self.lock = threading.Lock()
        self.reload()

    def __getitem__(self, key):
        self.get(key)

    def dbaccess(func):
        def funcwrap(self, *args, **kwargs):
            with self.lock:
                if self.db_path is not None:
                    import sqlite3
                    dbcon = sqlite3.connect(self.db_path)
                else:
                    dbcon = None
                temp = None
                try:
                    kwargs["dbcon"] = dbcon
                    temp = func(self, *args, **kwargs)
                except Exception as exc:
                    if hasattr(exc, "__traceback__"):
                        st = "{}\n\n{}".format(exc, traceback.format_tb(exc.__traceback__))
                    else:
                        st = "{}".format(exc)
                    logging.error(st)
                dbcon.close()
            return temp
        return funcwrap

    @dbaccess
    def reload(self, dbcon=None):
        if self.db_path is None:
            return
        cur = dbcon.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS main(name TEXT, val TEXT,PRIMARY KEY(name));''')
        # initialise with "False"
        cur.execute('''INSERT OR IGNORE INTO main(name,val) values ("state","False");''')
        dbcon.commit()

    @dbaccess
    def update(self, _defaults, overlays=None, dbcon=None):
        # unchangeable default
        _defaults["state"] = ("False", bool, "is component active")
        self.defaults = {}
        self.overlays = {}
        if overlays:
            _overlays = overlays
        else:
            _overlays = {}
        for _key, elem  in _defaults.items():
            tmp = None
            if len(elem) == 2:
                tmp = [elem[0], elem[1], ""]
            elif len(elem) == 3:
                tmp = list(elem)
            if tmp is None:
                logging.error("invalid default tuple: key: %s tuple: %s", _key, elem)
                return False
            if not isinstance(tmp[0], str) or not check_conftype(tmp[0], tmp[1]): # must be string and convertable
                return False
            self.defaults[_key] = tmp
        for _key, elem  in _overlays.items():
            tmp = None
            if not isinstance(elem[0], (str, None)): # must be string
                logging.error("invalid config object: %s", elem)
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
                logging.error("invalid default tuple: key: %s tuple: %s", _key, elem)
                return False
            if _key in self.defaults:
                if tmp[1] != self.defaults[_key][1]:
                    logging.error("converter mismatch between defaults: %s and overlays: %s", self.defaults[_key][1], tmp[1])
                    return False
            if not check_conftype(tmp[0], tmp[1]):
                return False
            self.overlays[_key] = tmp
        if dbcon is None:
            return True
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM main;''')
        _in_db = cur.fetchall()
        for _key, (_value, _type, _doc) in _defaults.items():
            cur.execute('''INSERT OR IGNORE INTO main(name,val) values (?,?);''', (_key, _value))
        if _in_db is None:
            return True
        for elem in _in_db:
            if elem[0] not in _defaults:
                cur.execute('''DELETE FROM main WHERE name=?;''', (elem[0],))
        dbcon.commit()
        return True

    @dbaccess
    def set(self, key, value, dbcon=None):
        if not isinstance(key, str):
            logging.error("key not a string")
            return False
        if key in self.overlays and not check_conftype(value, self.overlays[key][1]):
            #logging.error("overlays value type missmatch")
            return False
        elif key in self.defaults and not check_conftype(value, self.defaults[key][1]):
            #logging.error("invalid defaults value type")
            return False
        elif key not in self.defaults and key not in self.overlays:
            logging.error("not in defaults/overlays")
            return False
        if value is None:
            value = ""
        elif isinstance(value, bytes):
            value = str(value, "utf-8")
        else:
            value = str(value)
        if key in self.overlays or dbcon is None:
            self.overlays[key][0] = value
        elif dbcon is not None:
            cur = dbcon.cursor()
            cur.execute('''UPDATE main SET val=? WHERE name=?;''', (value, key))
            dbcon.commit()
        return True

    def set_default(self, key):
        if key not in self.defaults:
            return False
        return self.set(key, self.defaults[key][0])

    @dbaccess
    def get(self, _key, dbcon=None):
        """ get converted value """
        if not isinstance(_key, str):
            logging.error("key is no string")
            return None
        # key can be in overlays but not in defaults
        if _key in self.overlays:
            ret = self.overlays[_key][0]
            _converter = self.overlays[_key][1]
        else:
            if _key not in self.defaults:
                logging.error("\"%s\" is no key", _key)
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
    def list(self, onlypermanent=False, dbcon=None):
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
                logging.error("invalid element %s", elem)
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
            if not isinstance(_val2, str):
                logging.info("value should be str")
            if onlypermanent and ispermanent:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
            elif not onlypermanent:
                ret.append((_key, _val2, str(_converter), _defaultval, _doc, ispermanent))
        return ret
    
    @classmethod
    def defaults_from_json(cls, dbpath, jstring=None, jpath=None, overlays=None, ensure=None):
        if ensure:
            defaults = ensure.copy()
        else:
            defaults = {}
        try:
            if jpath:
                with open(jpath, "r") as readob:
                    defaults = json.load(readob)
            elif jstring:
                defaults = json.load(jstring)
            else:
                return None
            convert_config(defaults)
            if not verify_config(defaults):
                return None
            tconf = cls(dbpath)
            # if update is success return tconf
            if tconf.update(defaults, overlays):
                return tconf
        except Exception as exc:
            if hasattr(exc, "__traceback__"):
                st = "{}\n\n{}".format(exc, traceback.format_tb(exc.__traceback__))
            else:
                st = "{}".format(exc)
            logging.error(st)
        return None

def pluginresources_creater(_dict, requester):
    if requester == "":
        return None # crash instead
    def wrap(res):
        ob = _dict.get(res)
        if ob is None:
            logging.error("Resource: %s not available", res)
            return None
        elif callable(ob):
            def wrap2(*args, **kwargs):
                kwargs["requester"] = requester
                return ob(*args, **kwargs)
            return wrap2
        else:
            return ob.copy()
    return wrap

class pluginmanager(object):
    pluginenv = None
    pathes_plugins = None
    path_plugins_config = None
    resources = None
    interfaces = None
    plugins = None
    redirect_addr = None

    def __init__(self, _pathes_plugins, _path_plugins_config, scn_type, resources={}, pluginenv={}):
        # init here because of multiple instances
        self.interfaces = []
        self.plugins = {}
        self.redirect_addr = ""
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
            if os.path.isdir(path):
                for plugin in os.listdir(path):
                    if plugin in ["__pycache__", ""] or plugin[0] in " \t\b" or plugin[-1] in " \t\b":
                        continue
                    newpath = os.path.join(path, plugin)
                    if os.path.isdir(newpath) and os.path.isfile(os.path.join(newpath, pluginstartfile)) and plugin not in temp:
                        temp[plugin] = path
        return temp

    def plugin_is_active(self, plugin):
        pconf = configmanager(os.path.join(self.path_plugins_config, "{}{}".format(plugin, confdb_ending)))
        return pconf.getb("state")

    def clean_plugin_config(self):
        lplugins = self.list_plugins()
        lconfig = os.listdir(self.path_plugins_config)
        for dbconf in lconfig:
            #remove .confdb from name
            if dbconf[:-len(confdb_ending)] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config, dbconf))

    def load_pluginconfig(self, plugin_name, pluginpath=None):
        if pluginpath is None:
            pluginlist = self.list_plugins()
            pluginpath = pluginlist.get(plugin_name)
        if pluginpath is None:
            return None
        dbpath = os.path.join(self.path_plugins_config, "{}{}".format(plugin_name, confdb_ending))
        dbdefaults = os.path.join(pluginpath, plugin_name, pluginconfigdefaults)
        # no overlays for plugins
        if os.path.isfile(dbdefaults):
            pconf = configmanager.defaults_from_json(dbpath, jpath=dbdefaults, ensure={"pwhash": (str, "", "hashed password, empty for none")})
        else:
            pconf = configmanager(dbpath)
            pconf.update({"pwhash": (str, "", "hashed password, empty for none")})
        return pconf

    def init_plugins(self):
        lplugins = self.list_plugins()
        for plugin in lplugins.items():
            pconf = self.load_pluginconfig(plugin[0])
            if pconf is None or not pconf.getb("state"):
                continue
            if hasattr(importlib.util, "module_from_spec"):
                module = importlib.machinery.ModuleSpec("_plugins.{}".format(plugin[0]), None, origin=plugin[1])
                module.submodule_search_locations = [os.path.join(plugin[1], plugin[0]), plugin[1]]
                module = importlib.util.module_from_spec(module)
            else:
                module = types.ModuleType("_plugins.{}".format(plugin[0]), None)
                module.__path__ = [os.path.join(plugin[1], plugin[0]), plugin[1]]
            sys.modules[module.__name__] = module
            #print(sys.modules.get("plugins"),sys.modules.get("plugins.{}".format(plugin[0])))
            globalret = self.pluginenv.copy()
            globalret["__name__"] = "_plugins.{}.{}".format(plugin[0], pluginstartfile.rsplit(".", 1)[0])
            globalret["__package__"] = "_plugins.{}".format(plugin[0])
            globalret["__file__"] = os.path.join(plugin[1], plugin[0], pluginstartfile)
            finobj = None
            try:
                with open(os.path.join(plugin[1], plugin[0], pluginstartfile), "r") as readob:
                    exec(readob.read(), globalret)
                    finobj = globalret["init"](self.interfaces.copy(), pconf, pluginresources_creater(self.resources, plugin[0]), os.path.join(plugin[1], plugin[0]))
            except Exception as exc:
                st = "Plugin failed to load, reason:\n{}".format(exc)
                if hasattr(exc, "tb_frame"):
                    st += "\n\n{}".format(traceback.format_tb(exc))
                logging.error(st)
                finobj = None
            if finobj:
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

    def __init__(self, dbpath):
        import sqlite3
        self.db_path = dbpath
        self.lock = threading.Lock()
        try:
            con = sqlite3.connect(self.db_path)
        except Exception as exc:
            logging.error(exc)
            return
        self.lock.acquire()
        try:
            con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, security TEXT, certreferenceid INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
            con.execute('''CREATE TABLE if not exists certreferences(certreferenceid INTEGER, certreference TEXT, type TEXT, PRIMARY KEY(certreferenceid,certreference), FOREIGN KEY(certreferenceid) REFERENCES certs(certreferenceid) ON DELETE CASCADE);''')
            #hack:
            con.execute('''CREATE TABLE if not exists certrefcount(certreferenceid INTEGER);''')
            con.execute('''INSERT INTO certrefcount(certreferenceid) values(?);''', (0,))
            con.commit()
        except Exception as exc:
            con.rollback()
            logging.error(exc)
        con.close()
        self.lock.release()

    def connecttodb(func):
        import sqlite3
        def funcwrap(self, *args, **kwargs):
            temp = None
            self.lock.acquire()
            try:
                dbcon = sqlite3.connect(self.db_path)
                kwargs["dbcon"] = dbcon
                temp = func(self, *args, **kwargs)
                dbcon.close()
            except Exception as exc:
                st = str(exc)
                if "tb_frame" in exc.__dict__:
                    st = "{}\n\n{}".format(st, traceback.format_tb(exc))
                logging.error("%s\n%s", st, type(func).__name__)
            self.lock.release()
            return temp
        return funcwrap

    @connecttodb
    def addentity(self, _name, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is not None:
            logging.info("name exist: %s", _name)
            return False
        if not check_name(_name):
            logging.info("name contains invalid elements")
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values (?,'default');''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delentity(self, _name, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            #logging.info("name does not exist: %s", _name)
            return True
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def renameentity(self, _name, _newname, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logging.info("name does not exist: %s", _name)
            return False
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is not None:
            logging.info("newname already exist: %s", _newname)
            return False
        cur.execute('''UPDATE certs SET name=? WHERE name=?;''', (_newname, _name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self, _name, _certhash, nodetype="unknown", priority=20, security="valid", dbcon=None):
        if _name is None:
            logging.error("name None")
        if nodetype is None:
            logging.error("nodetype None")
        if not check_hash(_certhash):
            logging.error("hash contains invalid characters: %s", _certhash)
            return False
        if not check_security(security):
            logging.error("security is invalid type: %s", security)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone() is None:
            logging.info("name does not exist: %s", _name)
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname = cur.fetchone()
        if _oldname is not None:
            logging.info("hash already exist: %s", _certhash)
            return False

        # hack
        cur.execute('''SELECT certreferenceid FROM certrefcount''')
        count = cur.fetchone()[0]
        cur.execute('''UPDATE certrefcount SET certreferenceid=?''', (count+1,))
        # hack end
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,security,certreferenceid) values(?,?,?,?,?,?);''', (_name, _certhash, nodetype, priority, security, count))
        dbcon.commit()
        return True

    @connecttodb
    def movehash(self, _certhash, _newname, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is None:
            logging.info("name does not exist: %s", _newname)
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (_certhash,))
        _oldname = cur.fetchone()
        if _oldname is None:
            logging.info("certhash does not exist: %s", _certhash)
            return False
        cur.execute('''UPDATE certs SET name=? WHERE certhash=?;''', (_newname, _certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def changetype(self, _certhash, _type, dbcon=None):
        if not check_typename(_type, max_typelength):
            logging.info("type contains invalid characters or is too long (maxlen: %s): %s", max_typelength, _type)
            return False
        if not check_hash(_certhash):
            logging.info("hash contains invalid characters")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: %s", _certhash)
            return False
        cur.execute('''UPDATE certs SET type=? WHERE certhash=?;''', (_type, _certhash))
        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self, _certhash, _priority, dbcon=None):
        #convert str to int and fail if either no integer in string format
        # or datatype is something else except int
        if isinstance(_priority, str) and not _priority.isdecimal():
            logging.info("priority can not parsed as integer: %s", _priority)
            return False
        elif isinstance(_priority, str):
            _priority = int(_priority)
        elif not isinstance(_priority, int):
            logging.info("priority has unsupported datatype: %s", type(_priority).__name__)
            return False
        if _priority < 0 or _priority > 100:
            logging.info("priority too big (>100) or smaller 0")
            return False
        if not check_hash(_certhash):
            logging.info("hash contains invalid characters: %s", _certhash)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: %s", _certhash)
            return False
        cur.execute('''UPDATE certs SET priority=? WHERE certhash=?;''', (_priority, _certhash))
        dbcon.commit()
        return True

    @connecttodb
    def changesecurity(self, _certhash, _security, dbcon=None):
        if not check_hash(_certhash):
            logging.info("hash contains invalid characters: %s", _certhash)
            return False
        if not check_security(_security):
            logging.error("security is invalid type: %s", _security)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            logging.info("hash does not exist: %s", _certhash)
            return False
        cur.execute('''UPDATE certs SET security=? WHERE certhash=?;''', (_security, _certhash))
        dbcon.commit()
        return True

    def updatehash(self, _certhash, certtype=None, priority=None, security=None):
        if certtype is not None:
            if not self.changetype(_certhash, certtype):
                return False
        if priority is not None:
            if not self.changepriority(_certhash, priority):
                return False
        if certtype is not None:
            if not self.changesecurity(_certhash, security):
                return False

    @connecttodb
    def delhash(self, _certhash, dbcon=None):
        if _certhash == "default":
            logging.error("tried to delete reserved hash 'default'")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (_certhash,))
        if cur.fetchone() is None:
            #logging.info("hash does not exist: %s", _certhash)
            return True
        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (_certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def get(self, _certhash, dbcon=None):
        if _certhash is None:
            return None
        if not check_hash(_certhash):
            logging.error("Invalid certhash: %s", _certhash)
            return None
        cur = dbcon.cursor()
        cur.execute('''SELECT name,type,priority,security,certreferenceid FROM certs WHERE certhash=?;''', (_certhash,))
        ret = cur.fetchone()
        if ret is not None and ret[0] == isself:
            logging.critical("\"%s\" is in the db", isself)
            return None
        return ret

    @connecttodb
    def listhashes(self, _name, _nodetype=None, dbcon=None):
        #if check_name(_name) == False:
        #    return None
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' ORDER BY priority DESC;''', (_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' AND type=? ORDER BY priority DESC;''', (_name, _nodetype))
        return cur.fetchall()
        #if out is None:
        #    return []
        #else:
        #    return out

    @connecttodb
    def listnodenames(self, _nodetype=None, dbcon=None):
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT DISTINCT name FROM certs ORDER BY name ASC;''')
        else:
            cur.execute('''SELECT DISTINCT name FROM certs WHERE type=? ORDER BY name ASC;''', (_nodetype,))
        out = cur.fetchall()
        if out is None:
            return None
        else:
            return [elem[0] for elem in out]

    @connecttodb
    def listnodenametypes(self, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT DISTINCT name,type FROM certs ORDER BY name ASC;''')
        return cur.fetchall()
        #if out is None:
        #    return None
        #else:
        #    return out

    @connecttodb
    def listnodeall(self, _nodetype=None, dbcon=None):
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

    def certhash_as_name(self, _certhash):
        ret = self.get(_certhash)
        if ret is None:
            return None
        else:
            return ret[0]

    @connecttodb
    def exist(self, _name, _hash=None, dbcon=None):
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
    def addreference(self, _referenceid, _reference, _reftype, dbcon=None):
        if not check_reference(_reference):
            logging.error("reference invalid: %s", _reference)
            return False
        if not check_reference_type(_reftype):
            logging.error("reference type invalid: %s", _reftype)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_referenceid, _reference))
        if cur.fetchone() is not None:
            logging.info("certreferenceid exist: %s", _referenceid)
            return False
        cur.execute('''INSERT INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (_referenceid, _reference, _reftype))
        dbcon.commit()
        return True

    @connecttodb
    def delreference(self, _certreferenceid, _reference, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            #logging.info("certreferenceid/reference does not exist: %s, %s", _certreferenceid, _reference)
            return True
        cur.execute('''DELETE FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def updatereference(self, _certreferenceid, _reference, _newreference, _newreftype, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone() is None:
            logging.info("certreferenceid/reference does not exist: %s, %s", _certreferenceid, _reference)
            return False
        if _reference != _newreference:
            cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _newreference))
            if cur.fetchone() is not None:
                logging.info("new reference does exist: %s, %s", _certreferenceid, _reference)
                return False
        if _reference != _newreference:
            cur.execute('''UPDATE certreferences SET certreference=?, type=? WHERE certreferenceid=? and certreference=?;''', (_newreference, _newreftype, _certreferenceid, _reference))
        else:
            cur.execute('''UPDATE certreferences SET type=? WHERE certreferenceid=? and certreference=?;''', (_newreftype, _certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def getreferences(self, _referenceid, _reftype=None, dbcon=None):
        if not isinstance(_referenceid, int):
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
    def movereferences(self, _oldrefid, _newrefid, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_oldrefid,))
        if cur.fetchone() is None:
            logging.info("src certrefid does not exist: %s", _oldrefid)
            return False
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_newrefid,))
        if cur.fetchone() is None:
            logging.info("dest certrefid does not exist: %s", _newrefid)
            return False
        cur.execute('''UPDATE certreferences SET certreferenceid=? WHERE certreferenceid=?;''', (_newrefid, _oldrefid))
        dbcon.commit()
        return True

    @connecttodb
    def copyreferences(self, oldrefid, newrefid, dbcon=None):
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (oldrefid,))
        if cur.fetchone() is None:
            logging.info("src certrefid does not exist: %s", oldrefid)
            return False
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (newrefid,))
        if cur.fetchone() is None:
            logging.info("dest certrefid does not exist: %s", newrefid)
            return False
        cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=?;''', (newrefid,))
        srclist = cur.fetchall()
        if srclist is None:
            srclist = []
        for _ref, _type in srclist:
            cur.execute('''INSERT OR IGNORE INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (newrefid, _ref, _type))
        dbcon.commit()
        return True

    #@connecttodb
    #def listreferences(self, dbcon, _reftype = None):
    #    cur = dbcon.cursor()
    #    cur.execute('''SELECT DISTINCT name,type FROM certreferences WHERE type ORDER BY name ASC;''',(_reftype, ))
    #    return cur.fetchall()

    @connecttodb
    def findbyref(self, _reference, dbcon=None):
        if not check_reference(_reference):
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
def scnparse_args(arg_list, _funchelp, default_args=dict(), overwrite_args=dict()):
    pluginpathes = []
    if len(arg_list) > 0:
        tparam = ()
        for elem in arg_list: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help", "h"]:
                print(_funchelp())
                sys.exit(0)
            elif elem in ["help-md", "help-markdown"]:
                if "markdown" in globals():
                    print(markdown.markdown(_funchelp().replace("<", "&lt;").replace(">", "&gt;").replace("[", "&#91;").replace("]", "&#93;")))
                    sys.exit(0)
                else:
                    print("markdown help not available", file=sys.stderr)
                    sys.exit(1)
            else:
                tparam = elem.split("=", 1)
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    tparam = (tparam[0], "True")
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

overwrite_plugin_config_args = \
{
    "config": [default_configdir, str, "<dir>: path to config dir"],
    "plugin": ["", str, "<name>: Plugin name"],
    "key": ["", str, "<name>: config key"],
    "value": ["", str, "<name>: config value"]
}

def plugin_config_paramhelp():
    temp_doc = "# parameters (non-permanent)\n"
    for _key, elem in sorted(overwrite_plugin_config_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, value: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc
