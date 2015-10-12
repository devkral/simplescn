#! /usr/bin/env python3

import sys,os
sharedir = None
if "__file__" not in globals():
    __file__ = sys.argv[0]

if sharedir is None:
    # use sys
    sharedir = os.path.dirname(os.path.realpath(__file__))

# append to pathes
if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)

from http.client import HTTPSConnection 
from http.server import BaseHTTPRequestHandler,HTTPServer
import time
import signal,threading
import socketserver
import logging
import json
#, base64
import ssl


import socket

from common import server_port, check_certs, generate_certs, init_config_folder, default_configdir, default_sslcont, check_name, dhash, commonscn, pluginmanager, safe_mdecode, logger, pwcallmethod, confdb_ending, check_argsdeco, scnauth_server, max_serverrequest_size, generate_error, gen_result, high_load, medium_load, low_load, very_low_load, InvalidLoadSizeError, InvalidLoadLevelError, generate_error_deco, default_priority, default_timeout
#configmanager,, rw_socket

server_reference_header = \
{
"User-Agent": "simplescn/0.5 (broadcast)",
"Authorization": 'scn {}', 
"Connection": 'close' # keep-alive
}

def broadcast_helper(_addr, _path, payload, _certhash, _timeout):
    try:
        con = HTTPSConnection(_addr,  timeout=_timeout)
        con.connect()
        pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        hashpcert = dhash(pcert)
        if hashpcert != _certhash:
            return
        _headers = server_reference_header.copy()
        _headers["X-client_cert"] = pcert
        con.request("POST", _path, body=payload, headers=_headers)
        con.close()
    except socket.timeout:
        pass
    except Exception as e:
        logger().debug(e)
        
class server(commonscn):
    capabilities = ["basic",]
    nhipmap = None
    nhipmap_cache = ""
    refreshthread = None
    links = None
    cert_hash = None
    scn_type = "server"
    
    # explicitly allowed, note: server plugin can activate
    # this by their own version of this variable
    allowed_plugin_broadcasts = set()
    
    # auto set by load balancer
    expire_time = None
    sleep_time = None

    validactions = {"register", "get", "dumpnames", "info", "cap", "prioty", "num_nodes"}
    
    def __init__(self,d):
        commonscn.__init__(self)
        self.nhipmap = {}
        self.nhipmap_cond = threading.Event()
        self.changeip_lock = threading.Lock()
        if len(very_low_load) != 2 or len(low_load) != 3 or len(medium_load) != 3 or len(high_load) != 3:
            raise (InvalidLoadSizeError())
            
        if high_load[0] < medium_load[0] or medium_load[0] < low_load[0]:
            raise (InvalidLoadLevelError())
        

        if d["name"] is None or len(d["name"]) == 0:
            logger().debug("Name empty")
            d["name"] = "<noname>"
        
        #self.msg=_msg
        if d["message"] is None or len(d["message"]) == 0:
            logger().debug("Message empty")
            d["message"] = "<empty>"
        
        self.priority = int(d["priority"])
        self.cert_hash = d["certhash"]
        self.name = d["name"]
        self.message = d["message"]
        self.update_cache()
        
        self.load_balance(0)
        self.refreshthread = threading.Thread(target=self.refresh_nhipmap, daemon=True)
        self.refreshthread.start()
        

    def __del__(self):
        commonscn.__del__(self)
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as e:
            logger().error(e)
            
    # private, do not include in validactions
    def refresh_nhipmap(self):
        while self.isactive:
            self.changeip_lock.acquire()
            e_time = int(time.time())-self.expire_time
            count = 0
            dump=[]
            for _name,hashob in self.nhipmap.items():
                for _hash, val in hashob.items():
                    if val["updatetime"] < e_time:
                        del self.nhipmap[_name][_hash]
                    else:
                        count += 1
                        dump.append((_name,_hash))
                if len(self.nhipmap[_name]) == 0:
                    del self.nhipmap[_name]
            ### don't annote list with "map" dict structure on serverside (overhead)
            self.cache["dumpnames"] = json.dumps(gen_result(dump, True))
            self.cache["num_nodes"] = json.dumps(gen_result(count, True))
            self.cache["update_time"] = json.dumps(gen_result(int(time.time()), True))
            self.changeip_lock.release()
            self.nhipmap_cond.clear()
            
            self.load_balance(count)
            time.sleep(self.sleep_time)
            # wait until hashes change
            self.nhipmap_cond.wait()
    
    # private, do not include in validactions
    def load_balance(self, size_nh):
        if size_nh >= high_load[0]:
            self.sleep_time, self.expire_time = high_load[1:]
        elif size_nh >= medium_load[0]:
            self.sleep_time, self.expire_time = medium_load[1:]
        elif size_nh >= low_load[0]:
            self.sleep_time, self.expire_time = low_load[1:]
        else:
            # very_low_load tuple mustn't have three items
            self.sleep_time, self.expire_time = very_low_load
    
    # private, do not include in validactions
    def check_register(self, addresst, _hash):
        try:
            _cert = ssl.get_server_certificate(addresst, ssl_version=ssl.PROTOCOL_TLSv1_2)
        except ConnectionRefusedError:
            return False, "use_stun"
        if _cert is None:
            return False, "no cert"
        if dhash(_cert) != _hash:
            return False, "hash does not match"
        return True, "registered_ip"
    
    @check_argsdeco({"name": (str, "client name"),"port": (str, "port on which the client runs")}, optional={"update": (list, "list of compromised name/hashes")})
    def register(self, obdict):
        """ register client """
        if check_name(obdict["name"])==False:
            return False, "invalid name"
        if obdict["clientcert"] is None:
            return False, "no cert"
        
        clientcerthash = dhash(obdict["clientcert"])
        ret = self.check_register((obdict["clientaddress"][0], obdict["port"]), clientcerthash)
        if ret[0] == False:
            return ret
        #con = HTTPSConnection(obdict["clientaddress"][0], obdict["port"])
        #for _upd in obdict.get("update", []):
            
            #check ownership broken certs by requesting them
        #    pass
        #con.close()
        self.changeip_lock.acquire(False)
        if obdict["name"] not in self.nhipmap:
            self.nhipmap[obdict["name"]]={}
        if clientcerthash not in self.nhipmap[obdict["name"]]:
            self.nhipmap[obdict["name"]][clientcerthash] = {}
        self.nhipmap[obdict["name"]][clientcerthash]["address"] = obdict["clientaddress"][0]
        self.nhipmap[obdict["name"]][clientcerthash]["port"] = obdict["port"]
        self.nhipmap[obdict["name"]][clientcerthash]["updatetime"] = int(time.time())
        self.nhipmap[obdict["name"]][clientcerthash]["stunsock"] = None
        self.changeip_lock.release()
        # notify that change happened
        self.nhipmap_cond.set()
        return ret
    
    
    @check_argsdeco({"hash":(str, "client hash"), "name":(str, "client name")}, optional={"stun":(bool, "shall open a stun connection when neccessary (default: False)")})
    def get(self, obdict):
        """ get address of a client with name, hash """
        if obdict["name"] not in self.nhipmap:
            return False, "name not exist"
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, "hash not exist"
            
        _obj = self.nhipmap[obdict["name"]][obdict["hash"]]
        if _obj.get("update"):
            _update = _obj.get("update")
            _obj = self.nhipmap[_obj["name"]][_obj["hash"]]
        else:
            _update = None
        if obdict.get("stun", True) and _obj["stunsock"]:
            pass# TO implement
        if _update:
            return True, {"address": _obj["address"], "port": _obj["port"], "stun": _obj["stunsock"]!=None, "update":_update}
        else:
            return True, {"address": _obj["address"], "port": _obj["port"], "stun": _obj["stunsock"]!=None}
    
    
    # limited by maxrequest size
    @check_argsdeco({"plugin":(str, "plugin"), "receivers": (list, "list with receivertuples"), "paction":(str, "plugin action"), "payload": (str, "stringpayload")})
    def broadcast_plugin(self, obdict):
        """ Broadcast to client plugins """
        _plugin = obdict.get("plugin")
        paction = obdict.get("paction").split("/", 1)[0]
        if (_plugin, paction) not in self.allowed_plugin_broadcasts:
            return False, "not in allowed_plugin_broadcasts"
        for elem in obdict.get("receivers"):
            if len(elem)!=2:
                logger.debug("invalid element: {}".format(elem))
                continue
            _name, _hash = elem
            if _name not in self.nhipmap:
                continue
            if _hash not in self.nhipmap[_name]:
                continue
            _telem2 = self.nhipmap[_name]
            broadcast_helper("{}:{}".format(_telem2.get("address", ""), _telem2.get("port", -1)), "/plugin/{}/{}".format(_plugin, obdict.get("paction")), bytes(obdict.get("payload"), "utf-8"))
        #requester=None):


    
    @generate_error_deco
    def access_server(self, action, requester=None, **obdict):
        if action in self.cache:
            return self.cache[action]
        if action not in ["get", "broadcast_plugin"]:
            return False, "no permission"
        try:
            return getattr(self, action)(obdict)
        except Exception as e:
            return False, e
    
    
    
class server_handler(BaseHTTPRequestHandler):
    server_version = 'simplescn/0.5 (server)'
    sys_version = "" # would say python xy, no need and maybe security hole
    
    links = None
    webgui = False
    
    auth_info = None
    statics = {}
    
    
    def scn_send_answer(self, status, ob, _type="application/json"):
        self.send_response(status)
        self.send_header("Content-Length", len(ob))
        self.send_header("Content-Type", "{}; charset=utf-8".format(_type))
        self.end_headers()
        self.wfile.write(ob)
        
    def html(self,page,lang="en"):
        if self.webgui == False:
            self.send_error(404,"no webgui")
            return
            
        _ppath=os.path.join(sharedir, "html",lang, page)
        
        fullob = None
        with open(_ppath, "rb") as rob:
            fullob = rob.read()
        if fullob is None:
            self.send_error(404, "file not found")
        else:
            self.scn_send_answer(200,  fullob, "text/html")
    
    
    def init_scn_stuff(self):
        useragent = self.headers.get("User-Agent", "")
        #print(useragent)
        if "simplescn" in useragent:
            self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth= _auth.strip().rstrip()
        if method == "scn":
            # is different from the body, so don't use header information
            self.auth_info = safe_mdecode(_auth, "application/json; charset=utf-8") 
        else:
            self.auth_info = None
        
        # hack around not transmitted client cert
        _rewrapcert = self.headers.get("X-certrewrap")
        if _rewrapcert is not None:
            cont = self.connection.context
            self.connection = self.connection.unwrap()
            self.connection = cont.wrap_socket(self.connection, server_side=False)
            self.client_cert = ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True))
            if _rewrapcert != dhash(self.client_cert):
                return False
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
            
        else:
            self.client_cert = None
        return True
    def handle_server(self, action):
        if action not in self.links["server_server"].validactions:
            self.send_error(400, "invalid action - server")
            return
        
        
        if self.links["auth"].verify("server", self.auth_info) == False:
            authreq = self.links["auth"].request_auth("server")
            ob = bytes(json.dumps(authreq), "utf-8")
            self.scn_send_answer(401, ob)
            return
        
        if action in self.links["server_server"].cache:
            ob = bytes(self.links["server_server"].cache[action], "utf-8")
            self.scn_send_answer(200, ob)
            return
        
        
        if self.headers.get("Content-Length", "").strip().rstrip().isdecimal() == False:
            self.send_error(411,"POST data+data length needed")
            return
            
        contsize=int(self.headers.get("Content-Length"))
        if contsize>max_serverrequest_size:
            self.send_error(431, "request too large")
        
        readob = self.rfile.read(int(self.headers.get("Content-Length")))
        # str: charset (like utf-8), safe_mdecode: transform arguments to dict 
        obdict = safe_mdecode(readob, self.headers.get("Content-Type", "application/json; charset=utf-8"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        if self.client_address[0][:7] == "::ffff:":
            obdict["clientaddress"] = (self.client_address[0][7:], self.client_address[1])
        else:
            obdict["clientaddress"] = (self.client_address[0], self.client_address[1])
        obdict["clientcert"] = self.client_cert
        obdict["headers"] = self.headers
        try:
            func = getattr(self.links["server_server"], action)
            success, result = func(obdict)[:2]
            jsonnized = json.dumps(gen_result(result, success))
        except Exception as e:
            error = generate_error("unknown")
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                error = generate_error(e)
            ob = bytes(json.dumps(gen_result(error, False)), "utf-8")
            self.scn_send_answer(500, ob)
            return
        if success == False:
            self.send_response(400)
        else:
            self.send_response(200)
        ob=bytes(jsonnized, "utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header('Content-Type', "application/json; charset=utf-8")
        self.send_header('Content-Length', len(ob))
        self.end_headers()
        self.wfile.write(ob)
        
    def do_GET(self):
        if self.init_scn_stuff() == False:
            return
        if self.path=="/favicon.ico":
            if "favicon.ico" in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics["favicon.ico"])
            else:
                self.send_error(404)
            return
        
        if self.webgui == False:
            self.send_error(404, "no webgui enabled")
        
        _path=self.path[1:].split("/")
        if _path[0] in ("","server","html","index"):
            self.html("server.html")
            return
        elif  _path[0]=="static" and len(_path)>=2:
            if _path[1] in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics[_path[1]])
            return
        elif len(_path)==2:
            self.handle_server(_path[0])
            return
        self.send_error(404, "not -found")

    def do_POST(self):
        if self.init_scn_stuff() == False:
            return
        splitted = self.path[1:].split("/",1)
        pluginm = self.links["server_server"].pluginmanager
        if len(splitted) == 1:
            resource = splitted[0]
            sub = ""
        else:
            resource = splitted[0]
            sub = splitted[1]
        if resource == "plugin":
            split2 = sub.split("/", 1)
            if len(split2) != 2:
                self.send_error(400, "no plugin/action specified", "No plugin/action was specified")
                return
            plugin, action = split2
            if plugin not in pluginm.plugins or hasattr(pluginm.plugins[plugin], "sreceive"):
                self.send_error(404, "plugin not available", "Plugin with name {} does not exist/is not capable of receiving".format(plugin))
                return
            try:
                pluginm.plugins[plugin].sreceive(action, self.connection, self.client_cert, dhash(self.client_cert))
            except Exception as e:
                logger().error(e)
                self.send_error(500, "plugin error", str(e))
                return
        elif resource == "server":
            self.handle_server(sub)
        else:
            self.send_error(404, "resource not found", "could not find {}".format(resource))
    
class http_server_server(socketserver.ThreadingMixIn, HTTPServer):
    sslcont = None

    def __init__(self, server_address, certfpath, address_family):
        self.address_family = address_family
        HTTPServer.__init__(self, server_address, server_handler, False)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv", pwcallmethod)
        self.socket = self.sslcont.wrap_socket(self.socket)


class server_init(object):
    config_path = None
    links = None
    
    def __init__(self,_configpath, **kwargs):
        self.links = {}
        self.config_path=_configpath
        _spath=os.path.join(self.config_path,"server")
        port = kwargs["port"]
        init_config_folder(self.config_path,"server")
        
        if check_certs(_spath+"_cert")==False:
            logger().debug("Certificate(s) not found. Generate new...")
            generate_certs(_spath+"_cert")
            logger().debug("Certificate generation complete")
        
        with open(_spath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()
        
        self.links["auth"] = scnauth_server(dhash(pub_cert))
        
        #server_handler.salt = os.urandom(8)
        if kwargs["spwhash"] is not None:
            self.links["auth"].init_realm("server", kwargs["spwhash"])
        elif kwargs["spwfile"] is not None:
            with open(kwargs["spwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth"].init_realm("server", dhash(pw))
        _message = None
        _name = None
        with open(_spath+"_name.txt", 'r') as readserver:
            _name = readserver.readline().strip().rstrip()
        with open(_spath+"_message.txt", 'r') as readservmessage:
            _message = readservmessage.read()
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))

        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            logger().error("Configuration error in {}\nshould be: <name>/<port>\nor name contains some restricted characters".format(_spath+"_name"))
        
        if port is not None:
            _port = int(port)
        elif len(_name) >= 2:
            _port = int(_name[1])
        else:
            _port = server_port
        
        
        serverd={"name": _name[0], "certhash": dhash(pub_cert),
                "priority": kwargs["priority"], "message":_message}
        
        server_handler.links = self.links
        
        
        self.links["server_server"] = server(serverd)
        
        # use timeout argument of BaseServer
        http_server_server.timeout = int(kwargs["timeout"])
        self.links["hserver"] = http_server_server(("", _port), _spath+"_cert", socket.AF_INET6)
        
    def serve_forever_block(self):
        self.links["hserver"].serve_forever()

    def serve_forever_nonblock(self):
        sthread = threading.Thread(target=self.serve_forever_block, daemon=True)
        sthread.start()



def signal_handler(_signal, frame):
    sys.exit(0)

def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
port=<number>: Port
spwhash=<hash>: hash of pw, higher preference than pwfile
spwfile=<file>: file with password (cleartext)
priority=<number>: set priority
timeout: socket timeout
webgui: enables webgui
""")

#### don't base on sqlite, configmanager as it increases complexity and needed libs
#### but optionally support plugins (some risk)

server_args={"config":default_configdir,
             "port": None,
             "spwhash": None,
             "spwfile": None,
             "webgui": None,
             "useplugins": None,
             "priority": str(default_priority),
             "timeout": str(default_timeout)}
    
if __name__ == "__main__":
    from common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) > 1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem= elem.strip("-")
            if elem in ["help","h"]:
                paramhelp()
                sys.exit(0)
            else:
                tparam = elem.split("=")
                if len(tparam) == 1:
                    tparam=elem.split(":")
                if len(tparam) == 1:
                    server_args[tparam[0]] = "True"
                    continue
                server_args[tparam[0]] = tparam[1]
    
    configpath = os.path.expanduser(server_args["config"])
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    #should be gui agnostic so specify here
    if server_args["webgui"] is not None:
        server_handler.webgui = True
        #load static files  
        for elem in os.listdir(os.path.join(sharedir, "static")):
            with open(os.path.join(sharedir, "static", elem), 'rb') as _staticr:
                server_handler.statics[elem]=_staticr.read()
                #against ssl failures
                if len(server_handler.statics[elem]) == 0:
                    server_handler.statics[elem] = b" "
    else:
        server_handler.webgui = False

    cm = server_init(configpath ,**server_args)
    if server_args["useplugins"] is not None:
        pluginpathes = [os.path.join(sharedir, "plugins")]
        pluginpathes.insert(1, os.path.join(configpath, "plugins"))
        plugins_config = os.path.join(configpath, "config", "plugins")

        os.makedirs(plugins_config, 0o750, True)
    
        pluginm = pluginmanager(pluginpathes, plugins_config, "server{}".format(confdb_ending))
        if server_args["webgui"] is not None:
            pluginm.interfaces+=["web",]
        cm.links["server_server"].pluginmanager = pluginm
        pluginm.resources["access"] = cm.links["server_server"].access_server
        pluginm.init_plugins()
        _broadc = cm.links["server_server"].allowed_plugin_broadcasts
        for _name, plugin in pluginm.plugins.items():
            if hasattr(plugin, "allowed_plugin_broadcasts"):
                for _broadfuncname in getattr(plugin, "allowed_plugin_broadcasts"):
                    _broadc.insert((_name, _broadfuncname))
        
    logger().debug("server initialized. Enter serveloop")
    cm.serve_forever_block()
