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

from http import client
from http.server import BaseHTTPRequestHandler,HTTPServer
import time
#import socket
import signal,threading
import socketserver #,socket
import logging
import json, base64
import ssl

from common import server_port, check_certs,generate_certs,init_config_folder, default_configdir, default_sslcont, check_name, rw_socket, dhash, commonscn, pluginmanager, safe_mdecode, logger, pwcallmethod, confdb_ending, check_argsdeco, scnauth_server, max_serverrequest_size, generate_error, gen_result, high_load, medium_load, low_load, very_low_load, InvalidLoadSizeError, InvalidLoadLevelError,generate_error_deco
#configmanager




class server(commonscn):
    capabilities = ["basic",]
    nhipmap = None
    nhipmap_cache = ""
    refreshthread = None
    links = None
    cert_hash = None
    scn_type = "server"
    
    # auto set by load balancer
    expire_time = None
    sleep_time = None

    validactions={"register", "get", "dumpnames", "info", "cap", "prioty", "num_nodes"}
    
    def __init__(self,d):
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
    
    @check_argsdeco({"hash": (str, "client hash"),"name": (str, "client name"),"port": (str, "port on which the client runs")})
    def register(self, obdict):
        """ register client """
        if check_name(obdict["name"])==False:
            return False, "invalid name"
        ret = self.check_register((obdict["clientaddress"][0], obdict["port"]), obdict["hash"])
        if ret[0] == False:
            return ret
        self.changeip_lock.acquire(False)
        if obdict["name"] not in self.nhipmap:
            self.nhipmap[obdict["name"]]={}
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            self.nhipmap[obdict["name"]][obdict["hash"]] = {}
        self.nhipmap[obdict["name"]][obdict["hash"]]["address"] = obdict["clientaddress"][0]
        self.nhipmap[obdict["name"]][obdict["hash"]]["port"] = obdict["port"]
        self.nhipmap[obdict["name"]][obdict["hash"]]["updatetime"] = int(time.time())
        self.changeip_lock.release()
        # notify that change happened
        self.nhipmap_cond.set()
        return ret
    
    
    @check_argsdeco({"hash":(str, "client hash"), "name":(str, "client name")})
    def get(self, obdict):
        """ get address of a client with name, hash """
        if obdict["name"] not in self.nhipmap:
            return False, "name not exist"
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, "hash not exist"
        return True, self.nhipmap[obdict["name"]][obdict["hash"]]
    
    
    @generate_error_deco
    def access_server(self, action, requester=None, **obdict):
        if action in self.cache:
            return self.cache[action]
        if action not in ["get",]:
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
        obdict["clientaddress"] = self.client_address
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
        self.init_scn_stuff()
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
        self.init_scn_stuff()
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
            if pluginm.redirect_addr not in ["", None]:
                sockd = self.links["server_server"].do_request(pluginm.redirect_addr, \
                                        self.path, requesttype = "POST")
                redout = threading.Thread(target=rw_socket, args=(self.connection, sockd))
                redout.daemon=True
                redout.run()
                rw_socket(sockd, self.connection)
                return
            
            if plugin not in pluginm.plugins or hasattr(pluginm.plugins[plugin], "receive"):
                self.send_error(404, "plugin not available", "Plugin with name {} does not exist/is not capable of receiving".format(plugin))
                return
            try:
                pluginm.plugins[plugin].receive(action, self.connection)
            except Exception as e:
                logger().error(e)
                self.send_error(500, "plugin error", str(e))
                return
        elif resource == "server":
            self.handle_server(sub)
        else:
            self.send_error(404, "resource not found", "could not find {}".format(resource))
    
class http_server_server(socketserver.ThreadingMixIn,HTTPServer):
    sslcont = None
    #address_family = socket.AF_INET6
    
    #def __del__(self):
    #    self.crappyssl.close()
  
    def __init__(self, server_address,certfpath):
        socketserver.TCPServer.__init__(self, server_address, server_handler)
        #self.crappyssl=workaround_ssl(certs[1])
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv", pwcallmethod)
        self.socket = self.sslcont.wrap_socket(self.socket)


class server_init(object):
    config_path=None
    links=None
    sthread=None
    
    def __init__(self,_configpath, **kwargs):
        self.links = {}
        self.config_path=_configpath
        _spath=os.path.join(self.config_path,"server")
        port=kwargs["port"]
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
            _name = readserver.readline()[:-1] # remove \n
        with open(_spath+"_message.txt", 'r') as readservmessage:
            _message = readservmessage.read()
            if _message[-1] in "\n":
                _message=_message[:-1]
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))

        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            logger().error("Configuration error in {}\nshould be: <name>/<port>\nor name contains some restricted characters".format(_spath+"_name"))
        
        if port is not None:
            _port=int(port)
        elif len(_name)>=2:
            _port=int(_name[1])
        else:
            _port=server_port
        
        
        serverd={"name": _name[0], "certhash": dhash(pub_cert),
                "priority": kwargs["priority"], "message":_message}
        
        server_handler.links=self.links
        
        
        self.links["server_server"]=server(serverd)
        #self.links["server_server"].configmanager=configmanager(self.config_path+os.sep+"main.config")
            #self.links["server_server"].pluginmanager.interfaces+=["server"]
        
        # use timeout argument of BaseServer
        http_server_server.timeout = int(kwargs["timeout"])
        self.links["hserver"]=http_server_server(("",_port),_spath+"_cert")
        
    def serve_forever_block(self):
        self.links["hserver"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()



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
             "port":None,
             "spwhash":None,
             "spwfile":None,
             "webgui":None,
             "useplugins":None,
             "priority":"20",
             "timeout":"30"}
    
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
    
    configpath=os.path.expanduser(server_args["config"])
    if configpath[-1]==os.sep:
        configpath=configpath[:-1]
    #should be gui agnostic so specify here
    if server_args["webgui"] is not None:
        server_handler.webgui = True
        #load static files  
        for elem in os.listdir(os.path.join(sharedir, "static")):
            with open(os.path.join(sharedir, "static", elem), 'rb') as _staticr:
                server_handler.statics[elem]=_staticr.read()
                #against ssl failures
                if len(server_handler.statics[elem])==0:
                    server_handler.statics[elem]=b" "
    else:
        server_handler.webgui = False

    cm=server_init(configpath ,**server_args)
    if server_args["useplugins"] is not None:
        pluginpathes=[os.path.join(sharedir, "plugins")]
        pluginpathes.insert(1, os.path.join(configpath, "plugins"))
        plugins_config = os.path.join(configpath, "config", "plugins")

        os.makedirs(plugins_config, 0o750, True)
    
        pluginm=pluginmanager(pluginpathes, plugins_config, "server{}".format(confdb_ending))
        if server_args["webgui"] is not None:
            pluginm.interfaces+=["web",]
        cm.links["server_server"].pluginmanager=pluginm
        pluginm.resources["access"] = cm.links["server_server"].access_server
        pluginm.init_plugins()
        
    logger().debug("server initialized. Enter serveloop")
    cm.serve_forever_block()
