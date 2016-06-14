
"""
stuff
license: MIT, see LICENSE.txt
"""

import os
import sys
import traceback
import threading
import logging
import json
import socket
import ssl

from http.server import BaseHTTPRequestHandler
import socketserver


from simplescn import config
from simplescn.config import isself


from simplescn.tools import check_name, check_hash, check_security, \
check_typename, check_reference, check_reference_type, \
dhash, safe_mdecode, default_sslcont, pwcallmethod

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

    class connecttodb(object):
        def __init__(self, func):
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
            #return funcwrap

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
        if not check_typename(_type, config.max_typelength):
            logging.info("type contains invalid characters or is too long (maxlen: %s): %s", config.max_typelength, _type)
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

class http_server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """ server part of client/server """
    sslcont = None
    rawsock = None
    timeout = None
    use_unix = False

    def __init__(self, _address, certfpath, _handler, pwmsg, timeout=config.default_timeout, use_unix=False):
        self.use_unix = use_unix
        
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
        self.timeout = timeout
        socketserver.TCPServer.__init__(self, _address, _handler, False)
        if not self.use_unix:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                # python for windows has disabled it
                # hope that it works without
                pass
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv", lambda: bytes(pwcallmethod(pwmsg), "utf-8"))
        self.socket = self.sslcont.wrap_socket(self.socket)

        try:
            self.server_bind()
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
        threading.Thread(target=self.serve_forever, daemon=True).start()


class commonscn(object):
    # replace not add elsewise bugs in multi instance situation
    capabilities = []
    info = None
    priority = None
    name = None
    message = None
    cert_hash = None
    scn_type = "unknown"
    pluginmanager = None
    isactive = True
    update_cache_lock = None

    # set in __init__, elsewise bugs in multi instance situation (references)
    cache = None

    def __init__(self):
        self.cache = {"cap": "", "info": "", "prioty": ""}
        self.update_cache_lock = threading.Lock()
    def __del__(self):
        self.isactive = False

    def update_cache(self):
        with self.update_cache_lock:
            self.cache["cap"] = json.dumps(gen_result({"caps": self.capabilities}, True))
            self.cache["info"] = json.dumps(gen_result({"type": self.scn_type, "name": self.name, "message":self.message}, True))
            self.cache["prioty"] = json.dumps(gen_result({"priority": self.priority, "type": self.scn_type}, True))


class commonscnhandler(BaseHTTPRequestHandler):
    links = None
    sys_version = "" # would say python xy, no need and maybe security hole
    auth_info = None
    client_cert = None
    client_certhash = None
    # replaced by function not init
    alreadyrewrapped = False
    client_address2 = None
    links = None
    
    rfile = None
    wfile = None
    connection = None

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
            if dokeepalive is None and status == 200:
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
        if "simplescn" in useragent:
            self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        else:
            logging.debug("unknown useragent: %s", useragent)

        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth = _auth.strip().rstrip()
        if method == "scn":
            # is different from the body, so don't use header information
            self.auth_info = safe_mdecode(_auth, "application/json; charset=utf-8")
        else:
            self.auth_info = None
        if self.client_address[0][:7] == "::ffff:":
            self.client_address2 = (self.client_address[0][7:], self.client_address[1])
        else:
            self.client_address2 = (self.client_address[0], self.client_address[1])
        # hack around not transmitted client cert
        _rewrapcert = self.headers.get("X-certrewrap", None)
        _origcert = self.headers.get("X-original_cert", None)
        if _rewrapcert is not None:
            cont = self.connection.context
            if not self.alreadyrewrapped:
                # wrap tcp socket, not ssl socket
                self.connection = self.connection.unwrap()
                self.connection = cont.wrap_socket(self.connection, server_side=False)
                self.alreadyrewrapped = True
            self.client_cert = ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True)).strip().rstrip()
            self.client_certhash = dhash(self.client_cert)
            if _rewrapcert.split(";")[0] != self.client_certhash:
                return False
            if _origcert and self.links.get("trusted_certhash", "") != "":
                if _rewrapcert == self.links.get("trusted_certhash"):
                    self.client_cert = _origcert
                    self.client_certhash = dhash(_origcert)
                else:
                    logging.debug("rewrapcert incorrect")
                    return False
            #self.rfile.close()
            #self.wfile.close()
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
        else:
            self.client_cert = None
            self.client_certhash = None
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
        obdict["clientaddress"] = self.client_address2
        obdict["client_cert"] = self.client_cert
        obdict["client_certhash"] = self.client_certhash
        obdict["headers"] = self.headers
        obdict["socket"] = self.connection
        return obdict

    def handle_usebroken(self, sub):
        # invalidate as attacker can connect while switching
        self.alreadyrewrapped = False
        self.client_cert = None
        self.client_certhash = None
        certfpath = os.path.join(self.links["config_root"], "broken", sub)
        if os.path.isfile(certfpath+".pub") and os.path.isfile(certfpath+".priv"):
            cont = default_sslcont()
            cont.load_cert_chain(certfpath+".pub", certfpath+".priv")
            oldsslcont = self.connection.context
            self.connection = self.connection.unwrap()
            self.connection = cont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            self.scn_send_answer(200, message="brokencert successfull", docache=False, dokeepalive=True)
        else:
            oldsslcont = self.connection.context
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.connection = self.connection.unwrap()
            self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            self.scn_send_answer(404, message="brokencert not found", docache=False, dokeepalive=True)

    def wrap_func(self, func, *args, **kwargs):
        self.send_response(200)
        self.send_header("Connection", "keep-alive")
        self.send_header("Cache-Control", "no-cache")
        if self.headers.get("X-certrewrap") is not None:
            self.send_header("X-certrewrap", self.headers.get("X-certrewrap").split(";")[1])
        self.end_headers()
        # send if not sent already
        self.wfile.flush()
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logging.error(exc)
            return False

    def do_auth(self, domain):
        if not self.links["auth_server"].verify(domain, self.auth_info):
            authreq = self.links["auth_server"].request_auth(domain)
            ob = bytes(json.dumps(authreq), "utf-8")
            self.cleanup_stale_data(config.max_serverrequest_size)
            self.scn_send_answer(401, body=ob, docache=False)
            return False
        return True



def generate_error(err):
    error = {"msg": "unknown", "type": "unknown"}
    if err is None:
        return error
    error["msg"] = str(err)
    if isinstance(err, str):
        error["type"] = ""
    else:
        error["type"] = type(err).__name__
        if hasattr(err, "__traceback__"):
            error["stacktrace"] = "".join(traceback.format_tb(err.__traceback__)).replace("\\n", "") #[3]
        elif sys.exc_info()[2] is not None:
            error["stacktrace"] = "".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", "")
    return error # json.dumps(error)

def generate_error_deco(func):
    def get_args(self, *args, **kwargs):
        resp = func(self, *args, **kwargs)
        if len(resp) == 4:
            _name = resp[2]
            _hash = resp[3]
        else:
            _name = isself
            _hash = self.cert_hash
        if not resp[0]:
            return False, generate_error(resp[1]), _name, _hash
        return resp
    return get_args

def gen_result(res, status):
    """ generate result """
    stdict = {}
    if status:
        stdict["status"] = "ok"
        stdict["result"] = res
    else:
        stdict["status"] = "error"
        stdict["error"] = res
    return stdict

def check_result(obdict, status):
    """ is result valid """
    if obdict is None:
        return False
    if "status" not in obdict:
        return False
    if status and "result" not in obdict:
        return False
    if not status and "error" not in obdict:
        return False
    return True

### logging ###

def logcheck(ret, level=logging.DEBUG):
    if ret[0]:
        return True
    else:
        if level != 0: # = logging.DEBUG
            try:
                fn, lno, func, sinfo = logging.root.findCaller(False)
            except ValueError: # fails on some interpreters
                fn, lno, func, sinfo = "(unknown file)", 0, "(unknown function)", None
            sinfo = ret[1].get("stacktrace", None)
            message = ret[1].get("msg", "")
            if message == "":
                message = "{levelname}:{line}:{funcname}: crashed".format(levelname=logging.getLevelName(level), line=lno, funcname=func)
            record = logging.root.makeRecord(logging.root.name, level, fn, lno, message, [], None, func, None, sinfo)
            logging.root.handle(record)
        return False


def loglevel_converter(loglevel):
    if isinstance(loglevel, int):
        return loglevel
    elif not loglevel.isdigit():
        if hasattr(logging, loglevel) and isinstance(getattr(logging, loglevel), int):
            return getattr(logging, loglevel)
        raise TypeError("invalid loglevel")
    else:
        return int(loglevel)



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


