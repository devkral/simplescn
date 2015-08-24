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
import traceback
import socket
import logging
import json, base64
import ssl

from common import server_port, check_certs,generate_certs,init_config_folder, default_configdir, default_sslcont, check_name, gen_passwd_hash, rw_socket, dhash, commonscn, pluginmanager, configmanager, safe_mdecode, logger, pwcallmethod, confdb_ending, check_args, scnauth_server, max_serverrequest_size, generate_error





class server(commonscn):
    capabilities = ["basic",]
    nhipmap = None
    nhipmap_etime = None
    nhipmap_cache = ""
    nhipmap_len = 0
    sleep_time = 1
    refreshthread = None
    links = None
    expire_time = 100
    cert_hash = None
    scn_type = "server"

    validactions={"register", "get", "listnames", "info", "cap", "prioty", "num_nodes"}
    
    def __init__(self,d):
        self.expire_time = int(d["expire"])*60 #in minutes
        self.nhipmap = {}
        self.nhipmap_etime = {}
        self.nhipmap_cond = threading.Event()
        self.changeip_lock = threading.Lock()
        self.refreshthread = threading.Thread(target=self.refresh_nhipmap)
        self.refreshthread.daemon = True
        self.refreshthread.start()
        
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
        self.cert_hash = d["certhash"]
        self.update_cache()

    def __del__(self):
        commonscn.__del__(self)
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as e:
            logger().error(e)
            
            
    def refresh_nhipmap(self):
        while self.isactive:
            self.changeip_lock.acquire()
            e_time = int(time.time())-self.expire_time
            for _name in self.nhipmap_etime:
                for _hash in self.nhipmap_etime[_name]:
                    if self.nhipmap_etime[_name][_hash] < e_time:
                        del self.nhipmap[_name][_hash]
                        del self.nhipmap_etime[_name][_hash]
                if len(self.nhipmap[_name])==0:
                    del self.nhipmap[_name]
                    del self.nhipmap_etime[_name]
            
            self.nhipmap_len = len(self.nhipmap)
            self.nhipmap_cache = json.dumps(self.nhipmap)
            self.changeip_lock.release()
            self.nhipmap_cond.clear()
            time.sleep(self.sleep_time)
            # wait until hashes change
            self.nhipmap_cond.wait()
    #private, do not include in validactions
    def check_register(self, obdict):
        if check_args(obdict, (("addresst",()),("certhash",str))) == False:
            return False, "check_args failed (server: check_register)"
        try:
            _cert = ssl.get_server_certificate(obdict["addresst"], ssl_version=ssl.PROTOCOL_TLSv1_2)
        except ConnectionRefusedError:
            return False, "use_stun"
        if _cert is None:
            return False, "no cert"
        if dhash(_cert) != obdict["certhash"]:
            return False, "hash does not match"
        return True, "registered_ip"
        
    def register(self, obdict): #_name,_hash,_port,_addr): # , _cert):
        if check_args(obdict, (("certhash",str),("name",str),("port",str))) == False:
            return False, "check_args failed (server: register)"
        if check_name(obdict["name"])==False:
            return False, "invalid name"
        ret = self.check_register({"addresst":(obdict["clientaddress"][0], obdict["port"]), "certhash":obdict["certhash"]})
        if ret[0] == False:
            return ret
        
        self.changeip_lock.acquire(False)
        if obdict["name"] not in self.nhipmap:
            self.nhipmap[obdict["name"]]={}
            self.nhipmap_etime[obdict["name"]]={}
        self.nhipmap[obdict["name"]][obdict["name"]]=(obdict["clientaddress"][0],obdict["port"])
        self.nhipmap_etime[obdict["name"]][obdict["certhash"]]=int(time.time())
            
        self.changeip_lock.release()
        # notify that change happened
        self.nhipmap_cond.set()
        return ret
    
    
    def get(self, obdict):
        if check_args(obdict, (("name",str),("hash",str))) == False:
            return False, "check_args failed (server: get)"
        if obdict["name"] not in self.nhipmap:
            return False, "name not exist"
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, "certhash not exist"
        return True, self.nhipmap[obdict["name"]][obdict["hash"]]
    
    def listnames(self, obdict):
        return True, self.nhipmap_cache
    
    def info(self, obdict):
        return True, self.cache["info"]
    
    def cap(self, obdict):
        return True, self.cache["cap"]
    
    def prioty(self, obdict):
        return True, self.cache["prioty"]

    def num_nodes(self, obdict):
        return True, self.nhipmap_len
    
    
class server_handler(BaseHTTPRequestHandler):

    server_version = 'simple scn server 0.5'
    
    need_address_cert = ["register",]
    
    links=None
    salt=None

    #server use pw
    spwhash=None
        
    #tunnel stuff
    istunnel=False
    tpwhash=None
    tbsize=1500
    ttimeout=None
    webgui=True
    
    answernonce = None
    spwveri = None
    tpwveri = None
    
    
    statics = {}
    
    def __init__(self, *args):
        BaseHTTPRequestHandler.__init__(self, *args)
        self.answernonce = str(base64.urlsafe_b64encode(os.urandom(10)), "utf-8")
        self.spwveri = None
        self.tpwveri = None
        
    def html(self,page,lang="en"):
        if self.webgui==False:
            self.send_error(404,"no webgui")
            return
            
        _ppath=os.path.join(sharedir, "html",lang, page)
        if os.path.exists(_ppath)==False:
            self.send_error(404,"file not exist")
            return
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        
        with open(_ppath,"rb") as rob:
            self.wfile.write(rob.read())
    
    def parse_request(self):
        BaseHTTPRequestHandler.parse_request(self)
        if self.headers.get("User-Agent", "").split("/", 1)[0].strip().rstrip() == "simplescn":
            self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        
        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth= _auth.strip().rstrip()
        if method != "scn":
            self.send_error(406, "Invalid auth method")
        self.auth_info = safe_mdecode(_auth, self.headers.get("Content-Type", "application/json; charset=utf-8"))
        if self.auth_info is None:
            self.send_error(406, "Parsing auth_info failed")

    def handle_server(self, action):
        if action not in self.links["server_server"].validactions:
            self.send_error(400, "invalid action - server")
            return
        
        if int(self.headers.get("Content-Length", "0"))>max_serverrequest_size:
            self.send_error(431, "request too large")
            return
        
        if self.links["auth"].verify("server", self.auth_info) == False:
            authreq = self.links["auth"].request_auth("server")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_response(401, json.dumps(authreq))
            self.end_headers()
            return
        
        # str: charset (like utf-8), safe_mdecode: transform arguments to dict 
        obdict = safe_mdecode(self.rfile.read(),self.headers.get("Content-Type"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        obdict["clientaddress"] = self.client_address
        obdict["headers"] = self.headers
            
        try:
            func=self.links["server_server"].__getattribute__(action)
            witherror, jsonnized = func(obdict)
        except Exception as e:
            response = {}
            error = generate_error("unknown")
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                error = generate_error(e)
            response["errors"] = [error,]
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_response(500, json.dumps(response))
            self.end_headers()
            return
        if witherror == True:
            self.send_response(400,bytes(jsonnized, "utf-8"))
        else:
            self.send_response(200,bytes(jsonnized, "utf-8"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header('Content-Type', "application/json; charset=utf-8")
        self.end_headers()
    
    def do_GET(self):
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
            else:
                self.send_error(404, "not -found")
            return
    
    def do_CONNECT(self):
        # deactivate
        if True or self.istunnel==False:
            self.send_error(404,"no tunnel/proxy allowed")
            return
        #if self.check_tpw()==False:
        #    self.send_error(407,self.salt)
        #    return
        splitted = self.path[1:].split("/")
        if len(splitted) != 2:
            self.send_error(400, "invalid path")
            return
        name, certhash = splitted
        client = self.links["server_server"].get({"name":name, "certhash":certhash})
        if client[0] == False:
            self.send_error(500)
            return
        try:
            sockd=self.connection.create_connection(client[1],self.ttimeout)
                
        except Exception:
            self.send_error(400,"Connection failed")
            return
        
        self.send_response(200)
        #self.send_header('Connection established')
        #self.send_header(self.version_string())
        self.end_headers()
        redout=threading.Thread(target=rw_socket,args=(self.connection,sockd))
        redout.daemon=True
        redout.run()
        rw_socket(sockd,self.connection)

    def do_POST(self):
        splitted = self.path[1:].split("/",1)
        pluginm = self.links["server_server"].pluginmanager
        if len(splitted) == 1:
            resource = splitted[0]
            sub = ""
        else:
            resource = splitted[0]
            sub = splitted[1]
        if resource == "plugin":
            if len(splitted) == 1:
                self.send_error(400, "no plugin specified", "No plugin was specified")
                return
            elif pluginm.redirect_addr not in ["", None]:
                sockd = self.links["server_server"].do_request(pluginm.redirect_addr, \
                                        self.path, requesttype = "POST")
                redout = threading.Thread(target=rw_socket, args=(self.connection, sockd))
                redout.daemon=True
                redout.run()
                rw_socket(sockd, self.connection)
                return
            
            if sub[0] not in pluginm.plugins or "receive" not in pluginm.plugins[sub].__dict__:
                self.send_error(404, "plugin not available", "Plugin with name {} does not exist/is not capable of receiving".format(sub[0]))
                return
            try:
                pluginm.plugins[sub].receive(self.connection)
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
        self.sslcont=default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv", pwcallmethod)
        self.socket=self.sslcont.wrap_socket(self.socket)


class server_init(object):
    config_path=None
    links=None
    sthread=None
    
    def __init__(self,_configpath, **kwargs):
        self.links = {}
        self.links["auth"] = scnauth_server()
        self.config_path=_configpath
        _spath=os.path.join(self.config_path,"server")
        port=kwargs["port"]
        init_config_folder(self.config_path,"server")
        
        #server_handler.salt = os.urandom(8)
        if kwargs["spwhash"] is not None:
            self.links["auth"].init_realm("server", kwargs["spwhash"])
        elif kwargs["spwfile"] is not None:
            op=open(kwargs["spwfile"], "r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            pw.close()
            self.links["auth"].init_realm("server", dhash(pw))
        if kwargs["tunnel"] is not None:
            server_handler.istunnel = True
        #if kwargs["tpwhash"] is not None:
        #    self.links["auth"].kwargs["tpwhash"]
        #elif kwargs["tpwfile"] is not None:
        #    op=open(kwargs["tpwfile"], "r")
        #    pw=op.readline()
        #    if pw[-1] == "\n":
        #        pw = pw[:-1]
        #    server_handler.tpwhash = dhash(pw)
        #    op.close()
        _message=None
        _name=None
        if check_certs(_spath+"_cert")==False:
            logger().debug("Certificate(s) not found. Generate new...")
            generate_certs(_spath+"_cert")
            logger().debug("Certificate generation complete")
        with open(_spath+"_name", 'r') as readserver:
            _name=readserver.readline()
        with open(_spath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()
        with open(_spath+"_message", 'r') as readservmessage:
            _message=readservmessage.read()
            if _message[-1] in "\n":
                _message=_message[:-1]
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))

        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            logger().error("Configuration error in {}\nshould be: <name>/<port>\nName has some restricted characters".format(_spath+"_name"))
        
        if port is not None:
            port=int(port)
        elif len(_name)>=2:
            _port=int(_name[1])
        else:
            _port=server_port
        
        
        serverd={"name": _name[0], "certhash": dhash(pub_cert),
                "priority": kwargs["priority"], "message":_message,
                "expire": kwargs["expire"]}
        
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
spwhash=<hash>: sha256 hash of pw, higher preference than pwfile
spwfile=<file>: file with password (cleartext)
priority=<number>: set priority
timeout: socket timeout
expire: time until client entry expires
tunnel: enable tunnel
webgui: enables webgui
""")

#### don't port to sqlite for now as it increases complexity and needed libs
#### but libs needed anyway by common
#### support plugins?

server_args={"config":default_configdir,
             "port":None,
             "spwhash":None,
             "spwfile":None,
             "tunnel":None, 
             "tpwhash":None,
             "tpwfile":None,
             "webgui":None,
             "useplugins":None,
             "priority":"20",
             "expire":"30",
             #"ttimeout":"600",
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
        server_handler.webgui=True
        #load static files  
        for elem in os.listdir(os.path.join(sharedir, "static")):
            with open(os.path.join(sharedir, "static", elem), 'rb') as _staticr:
                server_handler.statics[elem]=_staticr.read()
                #against ssl failures
                if len(server_handler.statics[elem])==0:
                    server_handler.statics[elem]=b" "
    else:
        server_handler.webgui=False
    
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
        pluginm.init_plugins()
        
    logger().debug("server started. Enter mainloop")
    cm.serve_forever_block()
