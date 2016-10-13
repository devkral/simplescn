
"""
stuff
license: MIT, see LICENSE.txt
"""

import os
import sys
import threading
import logging
import json
import socket
import ssl
import sqlite3

import http
from http.server import BaseHTTPRequestHandler
import socketserver


from . import config
from .config import isself, file_family

from .tools import dhash, safe_mdecode, default_sslcont, loglevel_converter
from .tools.checks import namestr, hashstr, securitystr, \
check_typename, check_reference, check_reference_type, check_local, check_permission, priorityint


# for config
def parsepath(inp):
    ret = os.path.expanduser(os.path.expandvars(inp))
    if ret[-1] in ["/", "\\"]:
        ret = ret[:-1]
    if sys.platform.startswith('win32'):
        ret = ret.replace("/", "\\")
    return ret

def parsebool(inp):
    return inp.lower() in ["y", "true", "t"]

def connecttodb(func):
    def funcwrap(self, *args, **kwargs):
        temp = None
        with self.lock:
            #try:
            dbcon = sqlite3.connect(self.db_path)
            kwargs["dbcon"] = dbcon
            temp = func(self, *args, **kwargs)
            dbcon.close()
            #except Exception as exc:
            #    st = "{} (dbfile: {})".format(exc, self.db_path)
            #    if hasattr(exc, "__traceback__"):
            #        st = "{}\n\n{}".format(st, "".join(traceback.format_tb(exc.__traceback__)).replace("\\n", ""))
            #    elif sys.exc_info()[2] is not None:
            #        st = "{}\n\n{}".format(st, "".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", ""))
            #    logging.error("%s\n%s", st, type(func).__name__)
            #    raise exc
        return temp
    return funcwrap

class CommonDbInit(object):
    @property
    def lock(self):
        raise NotImplementedError()
    def initdb(self, con):
        raise NotImplementedError()
    @classmethod
    def create(cls, dbpath):
        try:
            dbcon = sqlite3.connect(dbpath)
            os.chmod(dbpath, 0o600)
        except Exception as exc:
            logging.error(exc)
            return None
        ret = cls(dbpath)
        with ret.lock:
            try:
                ret.initdb(dbcon)
                dbcon.commit()
                dbcon.close()
                return ret
            except Exception as exc:
                dbcon.rollback()
                logging.error(exc)
                dbcon.close()
                return None

class PermissionHashDb(CommonDbInit):
    db_path = None
    lock = None

    def __init__(self, dbpath):
        self.db_path = dbpath
        self.lock = threading.Lock()

    def initdb(self, con):
        con.execute('''CREATE TABLE if not exists certperms(certhash TEXT, permission TEXT, PRIMARY KEY(certhash,permission));''')

    @connecttodb
    def add(self, certhash: hashstr, permission, dbcon=None) -> bool:
        """ add or update, permissions as  list """
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if not check_permission(permission):
            logging.error("not a valid permission: %s", permission)
            return False
        cur = dbcon.cursor()
        cur.execute('''INSERT OR UPDATE certhash INTO certperms(certhash,permission) VALUES(?,?);''', (certhash, permission))
        dbcon.commit()
        return True

    @connecttodb
    def delete(self, certhash, permission=None, dbcon=None) -> bool:
        """ delete permission(s) for certhash """
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if permission is not None and not check_permission(permission):
            logging.error("not a valid permission: %s", permission)
            return False
        cur = dbcon.cursor()
        if permission:
            cur.execute('''DELETE FROM certperms WHERE certhash=? and permission=?;''', (certhash, permission))
        else:
            cur.execute('''DELETE FROM certperms WHERE certhash=?;''', (certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def get(self, certhash, permission=None, dbcon=None) -> list:
        """ get permissions as list """
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        cur = dbcon.cursor()
        if permission:
            if not check_permission(permission):
                logging.error("not a valid permission: %s", permission)
                return None
            cur.execute('''SELECT permission FROM certperms WHERE certhash=? and permission=?;''', (certhash, permission))
        else:
            cur.execute('''SELECT permission FROM certperms WHERE certhash=?;''', (certhash,))
        ret = cur.fetchall()
        if ret is None:
            return None
        return [elem[0] for elem in ret]

    @connecttodb
    def exist(self, certhash, permission, dbcon=None) -> bool:
        """ exist permission for certhash """
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if not check_permission(permission):
            logging.error("not a valid permission: %s", permission)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT permission FROM certperms WHERE certhash=? and permission=?;''', (certhash, permission))
        return cur.fetchone() is not None

    @connecttodb
    def list(self, dbcon=None) -> list:
        """ list certhash,permission as list """
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash,permission FROM certperms;''')
        return cur.fetchall()

class CerthashDb(CommonDbInit):
    db_path = None
    lock = None

    def __init__(self, dbpath):
        self.db_path = dbpath
        self.lock = threading.RLock()

    def initdb(self, con):
        con.execute('''CREATE TABLE if not exists certs(name TEXT, certhash TEXT, type TEXT, priority INTEGER, security TEXT, certreferenceid INTEGER, PRIMARY KEY(name,certhash));''') #, UNIQUE(certhash)
        con.execute('''CREATE TABLE if not exists certreferences(certreferenceid INTEGER, certreference TEXT, type TEXT, PRIMARY KEY(certreferenceid,certreference), FOREIGN KEY(certreferenceid) REFERENCES certs(certreferenceid) ON DELETE CASCADE);''')
        #hack:
        con.execute('''CREATE TABLE if not exists certrefcount(certreferenceid INTEGER);''')
        con.execute('''INSERT INTO certrefcount(certreferenceid) values(?);''', (0,))

    @connecttodb
    def addentity(self, _name: namestr, dbcon=None) -> bool:
        assert _name in namestr, "invalid name {}".format(_name)
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if cur.fetchone():
            logging.info("name exist: %s", _name)
            return False
        cur.execute('''INSERT INTO certs(name,certhash) values (?,'default');''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def delentity(self, _name: namestr, dbcon=None) -> bool:
        assert _name in namestr, "invalid name {}".format(_name)
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE name=?;''', (_name,))
        ret = cur.fetchall()
        for elem in ret:
            cur.execute('''DELETE FROM certreferences WHERE certreferenceid=?;''', (elem[0],))
        cur.execute('''DELETE FROM certs WHERE name=?;''', (_name,))
        dbcon.commit()
        return True

    @connecttodb
    def renameentity(self, _name: namestr, _newname: namestr, dbcon=None) -> bool:
        assert _name in namestr, "invalid name {}".format(_name)
        assert _newname in namestr, "invalid newname {}".format(_newname)
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if not cur.fetchone():
            logging.warning("name does not exist: %s", _name)
            return False
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone():
            logging.warning("newname already exist: %s", _newname)
            return False
        cur.execute('''UPDATE certs SET name=? WHERE name=?;''', (_newname, _name,))
        dbcon.commit()
        return True

    @connecttodb
    def addhash(self, _name: namestr, certhash: hashstr, nodetype="unknown", priority=20, security="valid", dbcon=None) -> bool:
        assert _name in namestr, "invalid name {}".format(_name)
        assert nodetype, "nodetype None"
        if certhash not in hashstr:
            logging.error("invalid hash: %s", certhash)
            return False
        if security not in securitystr:
            logging.error("security is invalid: %s", security)
            return False
        if priority not in priorityint:
            logging.error("priority is invalid: %s", security)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        if not cur.fetchone():
            logging.warning("name does not exist: %s", _name)
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (certhash,))
        _oldname = cur.fetchone()
        if _oldname:
            logging.info("hash already exist: %s", certhash)
            return False

        # hack
        cur.execute('''SELECT certreferenceid FROM certrefcount''')
        count = cur.fetchone()[0]
        cur.execute('''UPDATE certrefcount SET certreferenceid=?''', (count+1,))
        # hack end
        cur.execute('''INSERT INTO certs(name,certhash,type,priority,security,certreferenceid) values(?,?,?,?,?,?);''', (_name, certhash, nodetype, priority, security, count))
        dbcon.commit()
        return True

    @connecttodb
    def movehash(self, certhash: hashstr, _newname: namestr, dbcon=None) -> bool:
        assert _newname in namestr, "invalid newname {}".format(_newname)
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_newname,))
        if cur.fetchone() is None:
            logging.warning("name does not exist: %s", _newname)
            return False
        cur.execute('''SELECT name FROM certs WHERE certhash=?;''', (certhash,))
        _oldname = cur.fetchone()
        if not _oldname:
            logging.warning("certhash does not exist: %s", certhash)
            return False
        cur.execute('''UPDATE certs SET name=? WHERE certhash=?;''', (_newname, certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def changetype(self, certhash: hashstr, _type, dbcon=None) -> bool:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if not check_typename(_type, config.max_typelength):
            logging.info("type contains invalid characters or is too long (maxlen: %s): %s", config.max_typelength, _type)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (certhash,))
        if not cur.fetchone():
            logging.warning("hash does not exist: %s", certhash)
            return False
        cur.execute('''UPDATE certs SET type=? WHERE certhash=?;''', (_type, certhash))
        dbcon.commit()
        return True

    @connecttodb
    def changepriority(self, certhash: hashstr, _priority, dbcon=None) -> bool:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if _priority not in priorityint:
            logging.error("priority either no int or out of range (0-100)")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (certhash,))
        if not cur.fetchone():
            logging.warning("hash does not exist: %s", certhash)
            return False
        cur.execute('''UPDATE certs SET priority=? WHERE certhash=?;''', (_priority, certhash))
        dbcon.commit()
        return True

    @connecttodb
    def changesecurity(self, certhash, _security: securitystr, dbcon=None) -> bool:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if _security not in securitystr:
            logging.error("security is invalid: %s", _security)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certhash FROM certs WHERE certhash=?;''', (certhash,))
        if not cur.fetchone():
            logging.warning("hash does not exist: %s", certhash)
            return False
        cur.execute('''UPDATE certs SET security=? WHERE certhash=?;''', (_security, certhash))
        dbcon.commit()
        return True

    def updatehash(self, certhash: hashstr, certtype=None, priority=None, security=None) -> bool:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        if certtype is not None:
            if not self.changetype(certhash, certtype):
                return False
        if priority is not None:
            if not self.changepriority(certhash, priority):
                return False
        if certtype is not None:
            if not self.changesecurity(certhash, security):
                return False

    @connecttodb
    def delhash(self, certhash: hashstr, dbcon=None) -> bool:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certhash=?;''', (certhash,))
        ret = cur.fetchone()
        if ret:
            cur.execute('''DELETE FROM certreferences WHERE certreferenceid=?;''', (ret[0],))
        cur.execute('''DELETE FROM certs WHERE certhash=?;''', (certhash,))
        dbcon.commit()
        return True

    @connecttodb
    def get(self, certhash, dbcon=None) -> tuple:
        assert certhash in hashstr, "invalid hash: {}".format(certhash)
        cur = dbcon.cursor()
        cur.execute('''SELECT name,type,priority,security,certreferenceid FROM certs WHERE certhash=?;''', (certhash,))
        ret = cur.fetchone()
        if ret and ret[0] == isself:
            logging.critical("\"%s\" is in the db", isself)
            return None
        return ret

    @connecttodb
    def listhashes(self, _name, _nodetype=None, dbcon=None) -> list:
        assert _name in namestr, "invalid name {}".format(_name)
        cur = dbcon.cursor()
        cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        # should be an error if name is not in db
        if not cur.fetchone():
            return None
        if _nodetype is None:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' ORDER BY priority DESC;''', (_name,))
        else:
            cur.execute('''SELECT certhash,type,priority,security,certreferenceid FROM certs WHERE name=? AND certhash!='default' AND type=? ORDER BY priority DESC;''', (_name, _nodetype))
        return cur.fetchall()

    @connecttodb
    def listnodenames(self, _nodetype=None, dbcon=None) -> list:
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
    def listnodenametypes(self, dbcon=None) -> list:
        cur = dbcon.cursor()
        cur.execute('''SELECT DISTINCT name,type FROM certs ORDER BY name ASC;''')
        return cur.fetchall()

    @connecttodb
    def listnodeall(self, _nodetype=None, dbcon=None) -> list:
        cur = dbcon.cursor()
        if _nodetype is None:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs ORDER BY name ASC, priority DESC;''')
        else:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs WHERE type=? ORDER BY name ASC, priority DESC;''', (_nodetype,))
        return cur.fetchall()

    # simplifies logic
    def certhash_as_name(self, certhash) -> tuple:
        """ quick lookup of name or None if not available """
        ret = self.get(certhash)
        if ret is None:
            return None
        else:
            return ret[0]

    @connecttodb
    def exist(self, _name, certhash=None, dbcon=None) -> bool:
        assert _name in namestr, "invalid name {}".format(_name)
        assert certhash in hashstr or certhash is None, "invalid hash: {}".format(certhash)
        cur = dbcon.cursor()
        if certhash is None:
            cur.execute('''SELECT name FROM certs WHERE name=?;''', (_name,))
        else:
            cur.execute('''SELECT name FROM certs WHERE name=? AND certhash=?;''', (_name, certhash))
        return cur.fetchone() is not None

    @connecttodb
    def existreference(self, _certreferenceid, _reference, dbcon=None):
        assert isinstance(_certreferenceid, int), "invalid certreferenceid"
        if not check_reference(_reference):
            logging.error("reference invalid: %s", _reference)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_certreferenceid, ))
        if not cur.fetchone():
            logging.error("referenceid does not exist: %s", _certreferenceid)
            return False
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        return cur.fetchone() is not None

    @connecttodb
    def addreference(self, _certreferenceid, _reference, _reftype, dbcon=None):
        assert isinstance(_certreferenceid, int), "invalid certreferenceid"
        if not check_reference(_reference):
            logging.error("reference invalid: %s", _reference)
            return False
        if not check_reference_type(_reftype):
            logging.error("reference type invalid: %s", _reftype)
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_certreferenceid, ))
        if not cur.fetchone():
            logging.error("referenceid does not exist: %s", _certreferenceid)
            return False
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if cur.fetchone():
            logging.info("certreference exist: %s", _reference)
            return False
        cur.execute('''INSERT INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (_certreferenceid, _reference, _reftype))
        dbcon.commit()
        return True

    @connecttodb
    def delreference(self, _certreferenceid, _reference, dbcon=None) -> bool:
        assert isinstance(_certreferenceid, int), "invalid certreferenceid"
        if not check_reference(_reference):
            logging.error("invalid reference")
            return False
        cur = dbcon.cursor()
        # just delete
        cur.execute('''DELETE FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def updatereference(self, _certreferenceid, _reference, _newreference, _newreftype, dbcon=None) -> bool:
        assert isinstance(_certreferenceid, int), "invalid certreferenceid"
        if not check_reference(_reference):
            logging.error("invalid reference")
            return False
        if not check_reference(_newreference):
            logging.error("invalid newreference")
            return False
        if not check_reference_type(_newreftype):
            logging.error("invalid referencetype")
            return False
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _reference))
        if not cur.fetchone():
            logging.warning("certreferenceid/reference does not exist: %s, %s", _certreferenceid, _reference)
            return False
        if _reference != _newreference:
            cur.execute('''SELECT certreferenceid FROM certreferences WHERE certreferenceid=? and certreference=?;''', (_certreferenceid, _newreference))
            if cur.fetchone():
                logging.warning("new reference does exist: %s, %s", _certreferenceid, _reference)
                return False
        cur.execute('''UPDATE certreferences SET certreference=?, type=? WHERE certreferenceid=? and certreference=?;''', (_newreference, _newreftype, _certreferenceid, _reference))
        dbcon.commit()
        return True

    @connecttodb
    def getreferences(self, _certreferenceid: int, reftype=None, dbcon=None):
        assert isinstance(_certreferenceid, int), "invalid certreferenceid"
        if reftype and not check_reference_type(reftype):
            logging.error("invalid referencetype")
            return None
        cur = dbcon.cursor()
        if reftype is None:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=? ORDER BY certreference ASC;''', (_certreferenceid,))
        else:
            cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=? and type=? ORDER BY certreference ASC;''', (_certreferenceid, reftype))
        return cur.fetchall()

    @connecttodb
    def movereferences(self, _oldrefid: int, _newrefid: int, dbcon=None) -> bool:
        assert isinstance(_oldrefid, int), "invalid oldrefid"
        assert isinstance(_newrefid, int), "invalid newrefid"
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_oldrefid,))
        if not cur.fetchone():
            logging.warning("src certrefid does not exist: %s", _oldrefid)
            return False
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (_newrefid,))
        if not cur.fetchone():
            logging.warning("dest certrefid does not exist: %s", _newrefid)
            return False
        cur.execute('''UPDATE certreferences SET certreferenceid=? WHERE certreferenceid=?;''', (_newrefid, _oldrefid))
        dbcon.commit()
        return True

    @connecttodb
    def copyreferences(self, oldrefid: int, newrefid: int, dbcon=None) -> bool:
        assert isinstance(oldrefid, int), "invalid oldrefid"
        assert isinstance(newrefid, int), "invalid newrefid"
        cur = dbcon.cursor()
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (oldrefid,))
        if not cur.fetchone():
            logging.warning("src certrefid does not exist: %s", oldrefid)
            return False
        cur.execute('''SELECT certreferenceid FROM certs WHERE certreferenceid=?;''', (newrefid,))
        if not cur.fetchone():
            logging.warning("dest certrefid does not exist: %s", newrefid)
            return False
        cur.execute('''SELECT certreference, type FROM certreferences WHERE certreferenceid=?;''', (newrefid,))
        srclist = cur.fetchall()
        if srclist is None:
            return False
        for _ref, _type in srclist:
            cur.execute('''INSERT OR IGNORE INTO certreferences(certreferenceid,certreference,type) values(?,?,?);''', (newrefid, _ref, _type))
        dbcon.commit()
        return True

    @connecttodb
    def findbyref(self, reference, reftype=None, dbcon=None):
        if not check_reference(reference):
            logging.error("invalid reference, %s", reference)
            return None
        if reftype and not check_reference_type(reftype):
            logging.error("invalid referencetype, %s", reftype)
            return None
        cur = dbcon.cursor()
        if reftype:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs WHERE certreferenceid IN (SELECT DISTINCT certreferenceid FROM certreferences WHERE certreference=? AND type=?) ORDER BY name ASC;''', (reference, reftype))
        else:
            cur.execute('''SELECT name,certhash,type,priority,security,certreferenceid FROM certs WHERE certreferenceid IN (SELECT DISTINCT certreferenceid FROM certreferences WHERE certreference=?) ORDER BY name ASC;''', (reference,))
        return cur.fetchall()

class SHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """ server part of client/server """
    sslcont = None
    rawsock = None
    timeout = None
    _listenthread = None
    use_unix = False
    # for more performance
    daemon_threads = False

    def __init__(self, _address, sslcont, _handler, use_unix=False):
        self.use_unix = use_unix
        self.sslcont = sslcont

        if self.use_unix:
            self.address_family = socket.AF_UNIX
            try:
                os.unlink(_address)
            except OSError:
                if os.path.exists(_address):
                    raise
        else:
            self.address_family = socket.AF_INET6
            self.allow_reuse_address = 1
        self.timeout = _handler.server_timeout
        socketserver.TCPServer.__init__(self, _address, _handler, False)
        if not self.use_unix:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                # python for windows has disabled it
                # hope that it works without
                pass
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.socket = self.sslcont.wrap_socket(self.socket)
        try:
            self.server_bind()
            if self.use_unix:
                os.chmod(_address, 0o600)
            self.server_activate()
        except:
            self.server_close()
            raise

    def get_request(self):
        con, addr = self.socket.accept()
        if self.use_unix:
            return con, ('', 0)
        else:
            return con, addr

    def server_bind(self):
        """Override server_bind to store the server name."""
        socketserver.TCPServer.server_bind(self)
        if self.use_unix:
            self.server_name = self.socket.getsockname()
            self.server_port = 0
            # valid port but wildcard and invalid as returned port
            # so use it
        else:
            host, port = self.socket.getsockname()[:2]
            self.server_name = host #socket.getfqdn(host)
            self.server_port = port

    def serve_forever_nonblock(self):
        # program doesn't terminate without daemon=True
        self._listenthread = threading.Thread(target=self.serve_forever, daemon=True)
        self._listenthread.start()

    def serve_join(self):
        self._listenthread.join()

class CommonSCN(object):
    # replace not add elsewise bugs in multi instance situation
    capabilities = None
    priority = None
    name = None
    message = None
    scn_type = "unknown"
    pluginmanager = None
    isactive = True
    update_cache_lock = None

    # set in __init__, elsewise bugs in multi instance situation (references)
    cache = None

    def __init__(self):
        if not self.capabilities:
            self.capabilities = []
        self.cache = {"cap": "", "info": "", "prioty": ""}
        self.update_cache_lock = threading.Lock()
    def __del__(self):
        self.isactive = False

    def update_cache(self):
        with self.update_cache_lock:
            self.cache["cap"] = json.dumps({"caps": self.capabilities})
            self.cache["info"] = json.dumps({"type": self.scn_type, "name": self.name, "message":self.message})
            self.cache["prioty"] = json.dumps({"priority": self.priority, "type": self.scn_type})


class CommonSCNHandler(BaseHTTPRequestHandler):
    links = None
    sys_version = "" # would say python xy, no need and maybe security hole
    # for keep-alive
    default_request_version = "HTTP/1.1"
    auth_info = None
    # replaced by function not init
    links = None
    rfile = None
    wfile = None
    connection = None
    etablished_timeout = config.default_timeout
    server_timeout = config.server_timeout
    certtupel = None

    # disconnects any client which doesn't run local
    onlylocal = False
    # signals that connection is local
    is_local = False

    def __init__(self, request, client_address, server):
        """ overwritten StreamRequestHandler __init__
            for is_local and quicker closing """
        self.certtupel = (None, None, None)
        self.request = request
        self.client_address = client_address
        self.server = server
        # set variable is_local
        self.is_local = self.server.address_family == file_family or check_local(self.client_address[0])
        # if onlylocal is True: return if not local
        if self.onlylocal and not self.is_local:
            return
        self.setup()
        try:
            self.handle()
        finally:
            self.finish()

    def log_request(self, code='-', size='-'):
        """Log an accepted request.
        This is called by send_response().
        """
        if config.harden_mode:
            return
        if isinstance(code, http.HTTPStatus):
            _code = code.value
        else:
            _code = code
        self.log_message('"%s" %s %s',
                         self.requestline, str(_code), str(size), logfunc=logging.debug)
    def log_error(self, lformat, *args):
        """ Log an error. """
        self.log_message(lformat, *args, logfunc=logging.error)

    def log_message(self, lformat, *args, logfunc=logging.debug):
        """ Log an arbitrary message. """
        logfunc("%s - - [%s] %s" %
                (self.address_string(),
                 self.log_date_time_string(),
                 lformat%args))

    def scn_send_answer(self, status, body=None, mime="application/json", message=None, docache=False, dokeepalive=None):
        if message:
            self.send_response(status, message)
        else:
            self.send_response(status)
        if body:
            self.send_header("Content-Length", len(body))
        if mime and body:
            self.send_header("Content-Type", "{}; charset=utf-8".format(mime))
        if self.headers.get("X-certrewrap") is not None:
            self.send_header("X-certrewrap", self.headers.get("X-certrewrap").split(";")[1])
        if not docache:
            self.send_header("Cache-Control", "no-cache")
        # if connection is closed don't set keep-alive implicit
        # don't break wrap implicit
        if dokeepalive is None and status == 200 and not self.close_connection:
            dokeepalive = True

        if dokeepalive:
            self.send_header('Connection', 'keep-alive')
        else:
            self.send_header('Connection', 'close')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def init_scn_stuff(self):
        useragent = self.headers.get("User-Agent", "")
        if "simplescn" not in useragent:
            logging.debug("unknown useragent: %s", useragent)
        #    self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        #else:

        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth = _auth.strip().rstrip()
        if method == "scn":
            # is different from the body, so don't use header information
            self.auth_info = safe_mdecode(_auth, "application/json; charset=utf-8")
        else:
            self.auth_info = None
        # hack around not transmitted client cert
        _rewrapcert = self.headers.get("X-certrewrap", None)
        if _rewrapcert is not None:
            cont = self.connection.context
            # wrap tcp socket, not ssl socket
            self.connection = self.connection.unwrap()
            self.connection = cont.wrap_socket(self.connection, server_side=False)
            client_cert = ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True)).strip().rstrip()
            client_certhash = dhash(client_cert)
            if _rewrapcert.split(";")[0] != client_certhash:
                return False
            validated_name = None
            if self.links.get("certtupel", (None, None, None))[1] == client_certhash:
                validated_name = isself
            elif "hashdb" in self.links:
                hashob = self.links["hashdb"].get(client_certhash)
                if hashob:
                    validated_name = (hashob[0], hashob[3]) #name, security
                    if validated_name[0] == isself:
                        return False
            self.certtupel = (validated_name, client_certhash, client_cert)
            #self.rfile.close()
            #self.wfile.close()
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
        else:
            self.certtupel = (None, None, None)
        return True

    def cleanup_stale_data(self, maxchars=config.max_serverrequest_size):
        if self.headers.get("Content-Length", "").strip().rstrip().isdecimal():
            # protect against big transmissions
            self.rfile.read(min(maxchars, int(self.headers.get("Content-Length"))))

    def parse_body(self, maxlength=None):
        if not self.headers.get("Content-Length", "").strip().rstrip().isdecimal():
            self.scn_send_answer(411, message="POST data+data length needed")
            return None
        contsize = int(self.headers.get("Content-Length"))
        if maxlength and contsize > maxlength:
            self.scn_send_answer(431, message="request too large", docache=False)
        readob = self.rfile.read(contsize)
        # str: charset (like utf-8), safe_mdecode: transform arguments to dict
        obdict = safe_mdecode(readob, self.headers.get("Content-Type"))
        if obdict is None:
            self.scn_send_answer(400, message="bad arguments")
            return None
        obdict["clientaddress"] = self.client_address
        obdict["origcertinfo"] = self.certtupel
        obdict["headers"] = self.headers
        obdict["socket"] = self.connection
        return obdict

    def handle_usebroken(self, brokenhash):
        # invalidate as attacker can connect while switching
        self.certtupel = (None, None, None)
        oldsslcont = self.connection.context
        self.connection = self.connection.unwrap()
        certfpath = os.path.join(self.links["config_root"], "broken", brokenhash)
        if os.path.isfile(certfpath+".pub") and os.path.isfile(certfpath+".priv"):
            cont = default_sslcont()
            cont.load_cert_chain(certfpath+".pub", certfpath+".priv")
            self.connection = cont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            self.scn_send_answer(200, message="brokencert successful", docache=False, dokeepalive=True)
        else:
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            if brokenhash == self.links["certtupel"][1]:
                self.scn_send_answer(404, message="brokencert is client cert", docache=False, dokeepalive=True)
            else:
                self.scn_send_answer(404, message="brokencert not found", docache=False, dokeepalive=True)

    def do_auth(self, domain):
        if not self.links["auth_server"].verify(domain, self.auth_info):
            authreq = self.links["auth_server"].request_auth(domain)
            ob = bytes(json.dumps(authreq), "utf-8")
            self.cleanup_stale_data(config.max_serverrequest_size)
            self.scn_send_answer(401, body=ob, docache=False)
            return False
        return True



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
