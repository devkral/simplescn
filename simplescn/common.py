
"""
stuff
license: MIT, see LICENSE.txt
"""

import os
import sys
import traceback
import threading
import logging

from simplescn import check_name, check_hash, check_security, check_typename, check_reference, check_reference_type, isself, loglevel_converter, max_typelength

# for config
def parsepath(inp):
    return os.path.expanduser(os.path.expandvars(inp))

def parsebool(inp):
    if inp.lower() in ["y", "true", "t"]:
        return True
    else:
        return False

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

own_help = """
# help:
  * help: help in markdown format
  * help-md, help-markdown: help in html format (parsed markdown)
"""

# default_args, overwrite_args are modified
def scnparse_args(arg_list, _funchelp, default_args):
    new_arglist = {}
    for key, val in default_args.items():
        new_arglist[key] = val[1](val[0])
    if len(arg_list) > 0:
        tparam = ()
        for elem in arg_list: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help", "h"]:
                print(own_help)
                print(_funchelp())
                sys.exit(0)
            elif elem in ["help-md", "help-markdown"]:
                try:
                    import markdown
                    print(markdown.markdown(own_help+_funchelp().replace("<", "&lt;").replace(">", "&gt;").replace("[", "&#91;").replace("]", "&#93;")))
                    sys.exit(0)
                except ImportError:
                    print("markdown help not available", file=sys.stderr)
                    sys.exit(1)
            else:
                tparam = elem.split("=", 1)
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    tparam = (tparam[0], "True")
                # autoconvert name to loglevel
                if tparam[0] == "loglevel":
                    tparam[1] = str(loglevel_converter(tparam[1]))
                    logging.root.setLevel(int(tparam[1]))
                if tparam[0] in default_args:
                    new_arglist[tparam[0]] = default_args[tparam[0]][1](tparam[1])
    return new_arglist
