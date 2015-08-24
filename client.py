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


from client_admin import client_admin
from client_safe import client_safe

#import SSL as ssln
#from OpenSSL import SSL,crypto
from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import socketserver
import logging
import traceback
import ssl
import signal,threading
import socket
import json, base64
import time
from urllib import parse
from os import path

from common import success, error, check_certs, generate_certs, init_config_folder, default_configdir, certhash_db, default_sslcont, parse_response, dhash, VALNameError, VALHashError, isself, check_name, check_hash, dhash_salt, gen_passwd_hash, commonscn, scnparse_url, AddressFail, pluginmanager, configmanager, check_reference, check_reference_type, pwcallmethod, rw_socket, notify, confdb_ending, VALMITMError, check_args, safe_mdecode


from common import logger


#"tdesthash": None,
#"cpwhash": None,
#"spwhash": None,
#"tpwhash":None,
reference_header = \
{
"User-Agent": "simplescn/0.5 (client)",
"Accept-Charset": "utf-8",
"Authorization": 'scn {}'
}
class client_client(client_admin, client_safe):
    name=None
    cert_hash=None
    sslcont=None
    hashdb = None
    links = None
    
    validactions=set()
    validactions_put={"command",}
    #_cache_help = None
    # "access"
    #pwcache={}
    
    def __init__(self, _name, _pub_cert_hash, _certdbpath, _links):
        self.links = _links
        self._cache_help = cmdhelp()
        self.name = _name
        self.cert_hash = _pub_cert_hash
        self.hashdb = certhash_db(_certdbpath)
        self.sslcont = default_sslcont()
        self.validactions.update(client_admin.validactions_admin)
        self.validactions.update(client_safe.validactions_safe)
        self._cache_help = cmdhelp()

    def do_request(self, _addr, _path, body={},dheader = {}, forceport=False, context=None):
        if context is None:
            context = self.sslcont
        sendheaders = reference_header.copy()
        for key, val in dheader:
            sendheaders[key] = val
        sendheaders["Content-Type"] = "application/json"
        
        auth_parsed = json.loads(sendheaders.get("Authorization", "scn {}"))
        
        _addr=scnparse_url(_addr,force_port=forceport)
        con=client.HTTPSConnection(_addr[0],_addr[1], context=context)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        hashpcert=dhash(pcert)
        if hashpcert==self.cert_hash:
            val = isself
        elif body.get("certhash") is not None and body.get("certhash") != hashpcert:
            raise(VALHashError)
        else:
            val = self.hashdb.certhash_as_name(hashpcert)
            if val == isself:
                raise(VALNameError)

        if body.get("destname") is not None and body.get("desthash") is not None:
            con.putrequest("CONNECT", "/{}/{}".format(body.get("destname"), body.get("desthash")))
            con.set_tunnel(_addr,{"Proxy-Authorization": sendheaders.get("Proxy-Authorization","scn {}"),})
        
        con.putrequest("POST", requeststr)
        for key, val in sendheader.items():
            if key != "Proxy-Authorization":
                con.putheader(key, val)
        
        con.endheaders(json.dumps(body))
        
        #if requesttype == "POST" and body is None:
        #    return con.sock
        r=con.getresponse()
        if r.status == 401:
            reqob=safe_mdecode(r.read(), r.headers.get("Content-Type","application/json; charset=utf-8"))
            if reqob is None:
                logger().error("Invalid password request object")
                return None 
            realm, authob = self.links["auth"].auth(pwcallmethod("Please enter password for {}:\n".format(reqob["realm"]))(), reqob)
            auth_parsed[realm] = authob
            return self.do_request(_addr, _path, body=None, dheader=sendheaders, forceport=forceport, requesttype=requesttype, pwhashes=newpwhashes)
        else:
            if len(auth_struct)>0:
                pass
                #implement later
                #if r.getheader("Authorization-Answer") is None:
                #    raise(VALMITMError)
                #for elem in pwhashes.items():
                #    if r.getheader(elem[0], "") != dhash_salt(hashpcert, "{}:{}".format(_nonce,elem[1])):
                #        raise(VALMITMError)
            resp=parse_response(r)
            con.close()
            return resp[0],resp[1],val,hashpcert

    # command wrapper for cmd interfaces
    def command(self, _data):
        if type(_data) is str:
            inp = _data
        else:
            inp = str(_data, "utf-8")
        reqheader=reference_header.copy()
        ret = [False, None, self.cert_hash, isself ]
        if inp == "":
            return ret
        unparsed=inp.strip(" ").rstrip(" ")
        if unparsed[:5]=="hash/":
            ret[0] = True
            ret[1] = "Hash: {}".format(dhash(unparsed[6:]))
            return ret
        
        pos_header=unparsed.find("?")
        if pos_header!=-1:
            parsed=unparsed[:pos_header].split("/")
            tparam=unparsed[pos_header+1:].split("&")
            for elem in tparam:
                elem=elem.split("=")
                if len(elem)==1 and elem[0]!="":
                    reqheader[elem[0]]=""
                elif len(elem)==2:
                    reqheader[elem[0]]=elem[1]
                else:
                    ret[0] = False
                    ret[1] = "Error: invalid key/value pair\n{}".format(elem)
                    return ret
        else:
            parsed=unparsed.split("/")
        
        #call functions in plugins
        if str(parsed[0]) == "plugin":
            plugins=self.links["client_server"].pluginmanager.plugins
            if plugins is None:
                return
            if parsed[1] not in plugins:
                ret[0] = False
                ret[1] = "Error: plugin does not exist"
                return ret
            plugin = plugins[parsed[1]]
            if "cmd_node_actions" not in plugin.__dict__:
                ret[0] = False
                ret[1] = "Error: plugin does not support commandline"
                return ret
                
            action = str(parsed[2])
            if "cmd_node_localized_actions" in plugin.__dict__ and \
                    action in plugin.cmd_node_localized_actions:
                    action = plugin.cmd_node_localized_actions[action]
            try:
                
                resp = plugin.cmd_node_actions[action][0](*parsed[2:])
                ret[0] = True
                ret[1] = str(resp)
            except Exception as e:
                st="Error: {}\n".format(e)
                if "tb_frame" in e.__dict__:
                    st="{}\n{}\n\n".format(st,traceback.format_tb(e))
                st = "{}Errortype: {}\nCommandline: {}".format(st, type(e).__name__, parsed)
                ret[0] = False
                ret[1] = "Error:\n{}".format(st)
            return ret
        
        return self.access_main(str(parsed[0]),parsed[1:],reqheader)
    
    
    def access_data(self, func, _action, _data, dheader):
        if func in self.validactions_data and func != "access_data":
            #args2 = list(args)
            #args2.append(dheader)
            return self.__getattribute__(func)(_data, dheader)
        else:
            return None
    
    # NEVER include in validactions
    # for plugins, e.g. untrusted
    # requester = None, don't allow asking
    def access_safe(self, action, args, dheader, requester=None ):
        args = list(args)
        if action in self.validactions:
            if action not in self.validactions_safe:
                if requester is None or notify('"{}" wants admin permissions\nAllow(y/n)?: '.format(requester)):
                    return False, "no permission", isself, self.cert_hash
            if action in self.need_dheader:
                args = args.append(dheader)
            return self.__getattribute__(action)(*args)
        else:
            return False, "not in validactions", isself, self.cert_hash
    
    # NEVER include in validactions
    def access_main(self, action, args, dheader):
        args = list(args)
        if action in self.validactions:
            if action in self.need_dheader:
                args.append(dheader)
            try:
                return self.__getattribute__(action)(*args)
            except AddressFail as e:
                return False, "Addresserror:\n{}".format(e.msg), isself, self.cert_hash
            except ConnectionRefusedError:
                return False, "unreachable", isself, self.cert_hash
            except Exception as e:
                st="Error: {}\n".format(e)
                if "tb_frame" in e.__dict__:
                    st="{}\n{}\n\n".format(st,traceback.format_tb(e))
                st = "{}Errortype: {}\nCommandline: {}".format(st, type(e).__name__, st)
                return False, "Error:\n{}".format(st), isself, self.cert_hash
        else:
            return False, "not in validactions", isself, self.cert_hash


###server on client



class client_server(commonscn):
    capabilities = ["basic",]
    scn_type = "client"
    spmap = {}
    validactions = {"info", "getservice", "listservices", "cap", "prioty", "registerservice", "delservice"}
    local_client_service_control = False
    wlock = None
    def __init__(self, dcserver):
        self.wlock = threading.Lock()
        if dcserver["name"] is None or len(dcserver["name"]) == 0:
            logger().debug("Name empty")
            dcserver["name"] = "<noname>"

        if dcserver["message"] is None or len(dcserver["message"]) == 0:
            logger().debug("Message empty")
            dcserver["message"] = "<empty>"
            
        self.name = dcserver["name"]
        self.message = dcserver["message"]
        self.priority = dcserver["priority"]
        self.cert_hash = dcserver["certhash"]
        
        #self.update_cache()
    ### the primary way to add or remove a service
    ### can be called by every application on same client
    def registerservice(self, obdict):
        if check_args(obdict, (("service",str),("port",int))) == False:
            return False, "check_args failed (client_server:registerservice))"
        if obdict.get("clientaddress") in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            self.spmap[obdict.get("service")] = obdict.get("port")
            self.wlock.release()
            return success
        return False, "no permission"

    def delservice(self, obdict):
        if check_args(obdict, (("service",str),)) == False:
            return False, "check_args failed (client_server:delservice)"
        
        if obdict.get("clientaddress") in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            if obdict["service"] in self.spmap:
                del self.spmap[obdict["service"]]
            self.wlock.release()
            return  True, "success"
        return False, "no permission"
        
    ### management section - end ###
    
    def getservice(self, obdict):
        if check_args(obdict, (("service",str),)) == False:
            return False, "check_args failed (client_server:service)"
        if obdict["service"] not in self.spmap:
            return False, "service"
        return True, self.spmap[_service]

    def listservices(self, obdict):
        return True, self.spmap

    def info(self, obdict):
        return True, self.cache["info"]

    def cap(self, obdict):
        return True, self.cache["cap"]
    
    def prioty(self, obdict):
        return True, self.cache["prioty"]
    
class client_handler(BaseHTTPRequestHandler):
    server_version = 'simplescn/0.5 (client)'
    auth_info = None
    
    links = None
    handle_remote = False
    statics = {}
    webgui = False
    
    def html(self, page, lang = "en"):
        if self.webgui == False:
            self.send_error(404, "no webgui")
            return
        _ppath = os.path.join(sharedir, "html", lang, page)
        if os.path.exists(_ppath) == False:
            self.send_error(404, "file not exist")
            return
        self.send_response(200)
        self.send_header('Content-Type', "text/html")
        self.end_headers()
        with open(_ppath, "rb") as rob:
            self.wfile.write(rob.read())
            #.format(name=self.links["client_server"].name,message=self.links["client_server"].message),"utf8"))

        
    ### GET ###
    def handle_client(self, action, _auth):
        if action not in self.links["client"].validactions:
            self.send_error(400, "invalid action - client")
            return
        if self.handle_remote == False and not self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
            self.send_error(403, "no permission - client")
            return
        
        if action in self.links["client"].validactions_admin:
            if "admin" in self.links["auth"].realms:
                realm = "admin"
            else:
                realm = "client"
        else:
            realm = "client"
        if self.links["auth"].verify(realm, _auth) == False:
            authreq = self.links["auth"].request_auth(realm)
            self.send_header("Content-Type", "application/json")
            self.send_response(401, json.dumps(authreq))
            self.end_headers()
            return

        # str: charset (like utf-8), safe_mdecode: transform arguments to dict 
        obdict = safe_mdecode(self.rfile.read(),self.headers.get("Content-Type"),self.headers.get("Accept-Charset","utf-8"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        obdict["clientaddress"] = self.client_address
        obdict["headers"] = self.headers
        try:
            func = self.links["client"].__getattribute__(action)#self.links["client"].access_main(action, _cmdlist, self.headers)
            response = func(obdict)
            jsonnized = json.dumps(response)
        except AddressFail as e:
            self.send_error(500, e.msg)
            return
        except Exception as e:
            response = {}
            error = generate_error("unknown")
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                error = generate_error(e)
            response["errors"] = [error,]
            self.send_header("Content-Type", "application/json")
            self.send_response(500, json.dumps(error))
            self.end_headers()
            return
        if response.get("errors", None) is None:
            self.send_response(400, bytes(jsonnized, "utf-8"))
        else:
            self.send_response(200, bytes(jsonnized, "utf-8"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header('Content-Type', "application/json")
        self.end_headers()

    def handle_server(self, action, obdict):
        if action not in self.links["client_server"].validactions:
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
        obdict = safe_mdecode(str(self.rfile.read(),self.headers.get("Accept-Charset","utf-8")),self.headers.get("Content-Type"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        obdict["clientaddress"] = self.client_address
        obdict["headers"] = self.headers
        try:
            out = resp_st.copy()
            func = self.links["client_server"].__getattribute__(action)
            result=func(obdict)
            if len(result)==2:
                success, result = result
            else:
                success, result, certname, certhash = result
        except Exception as e:
            response = {}
            error = generate_error("unknown")
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                error = generate_error(e)
            response["error"] = error
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_response(500, json.dumps(error))
            self.end_headers()
            return
        
        if success:
            self.send_response(400,bytes(json.dumps(result), "utf-8"))
        else:
            self.send_response(200,bytes(json.dumps(result), "utf-8"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header('Content-Type', "application/json; charset=utf-8")
        self.end_headers()
    
    def do_GET(self):
        if self.path == "/favicon.ico":
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
    
    def parse_request(self):
        BaseHTTPRequestHandler.parse_request(self)
        if self.headers.get("User-Agent", "").split("/", 1)[0].strip().rstrip() == "simplescn":
            self.error_message_format = "%(code)d: %(message)s – %(explain)s"
        
        _auth = self.headers.get("Authorization", 'scn {}')
        method, _auth = _auth.split(" ", 1)
        _auth= _auth.strip().rstrip()
        if method != "scn":
            self.send_error(406, "Invalid auth method")
        self.auth_info = safe_mdecode(_auth)
        if self.auth_info is None:
            self.send_error(406, "Parsing auth_info failed")
    
    def do_POST(self):
        try:
            codecs.lookup(self.headers.get("Accept-Charset", "utf-8"))
        except Exception:
            self.send_error(406, "invalid charset - client")
            return
        
        splitted = self.path[1:].split("/",1)
        pluginm = self.links["client_server"].pluginmanager
        if len(splitted) == 1:
            resource = splitted[0]
            sub = ""
        else:
            resource = splitted[0]
            sub = splitted[1]
        
        if resource == "plugin":
            if len(sub) != 1:
                self.send_error(400, "no plugin specified", "No plugin was specified")
                return
            elif pluginm.redirect_addr not in ["", None]:
                sockd = self.links["client_client"].do_request(pluginm.redirect_addr, \
                                        self.path, requesttype = "POST")
                redout = threading.Thread(target=rw_socket, args=(self.connection, sockd))
                redout.daemon=True
                redout.run()
                rw_socket(sockd, self.connection)
                return
            
            if sub[0] not in pluginm.plugins or "receive" not in pluginm.plugins[plugin].__dict__:
                self.send_error(404, "plugin not available", "Plugin with name {} does not exist/is not capable of receiving".format(sub[0]))
                return
            try:
                pluginm.plugins[plugin].receive(action, self.connection)
            except Exception as e:
                logger().error(e)
                self.send_error(500, "plugin error", str(e))
                return
        elif resource == "server":
            self.handle_server(sub)
        elif resource == "client":
            self.handle_client(sub)
        else:
            self.send_error(404, "resource not found", "could not find {}".format(resource))
        
class http_client_server(socketserver.ThreadingMixIn,HTTPServer):
    """server part of client; inheritates client_server to provide
        client information"""
    #address_family = socket.AF_INET6
    sslcont = None
    
    
    def __init__(self, _client_address, certfpath):
        HTTPServer.__init__(self, _client_address, client_handler)
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv")
        self.socket = self.sslcont.wrap_socket(self.socket)
        


class client_init(object):
    config_root=None
    plugins_config=None
    links={}
    
    def __init__(self,confm,pluginm):
        self.links["config"]=confm
        self.links["config_root"]=confm.get("config")
        
        _cpath=os.path.join(self.links["config_root"],"client")
        init_config_folder(self.links["config_root"],"client")
        
        if confm.getb("webgui")!=False:
            logger().debug("webgui enabled")
            client_handler.webgui=True
            #load static files
            for elem in os.listdir(os.path.join(sharedir, "static")):
                with open(os.path.join(sharedir,"static",elem), 'rb') as _staticr:
                    client_handler.statics[elem]=_staticr.read()
        else:
            client_handler.webgui=False
        
        if confm.getb("cpwhash") == True:
            # ensure that password is set when allowing remote
            if confm.getb("remote") == True:
                client_handler.handle_remote = True
            client_handler.cpwhash=confm.get("cpwhash")
        elif confm.getb("cpwfile") == True:
            # ensure that password is set when allowing remote
            if confm.getb("remote") == True:
                client_handler.handle_remote = True
            op=open("r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            client_handler.cpwhash=dhash(pw)
            op.close()
        
        if confm.getb("apwhash") == True:
            client_handler.apwhash=confm.get("apwhash")
        elif confm.getb("apwfile") == True:
            op=open("r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            client_handler.apwhash=dhash(pw)
            op.close()
            
        if confm.getb("spwhash") == True:
            client_handler.spwhash = confm.get("spwhash")
        elif confm.getb("spwfile") == True:
            op=open("r")
            pw=op.readline()
            if pw[-1] == "\n":
                pw = pw[:-1]
            client_handler.spwhash = dhash(pw)
            op.close()
        
        if check_certs(_cpath+"_cert") == False:
            logger().debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logger().debug("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read()

        with open(_cpath+"_name", 'r') as readclient:
            _name = readclient.readline()
        with open(_cpath+"_message", 'r') as readinmes:
            _message = readinmes.read()
            if _message[-1] in "\n":
                _message = _message[:-1]
        #report missing file
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))
        
        _name = _name.split("/")
        if len(_name)>2 or check_name(_name[0]) == False:
            logger().error("Configuration error in {}\nshould be: <name>/<port>\nName has some restricted characters".format(_cpath+"_name"))
            sys.exit(1)

        if confm.getb("port") == True:
            port = int(confm.get("port"))
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = 0
        
        clientserverdict={"name": _name[0], "certhash": dhash(pub_cert),
                "priority": confm.get("priority"), "message":_message, 
                "nonces": None}
        
        self.links["client_server"] = client_server(clientserverdict)#_name[0], confm.get("priority"), dhash(pub_cert), _message)
        self.links["client_server"].pluginmanager=pluginm
        self.links["configmanager"] = confm

        client_handler.links=self.links
        
        # use timeout argument of BaseServer
        http_client_server.timeout=confm.get("timeout")
        self.links["server"]=http_client_server(("", port), _cpath+"_cert")
        self.links["client"]=client_client(_name[0], dhash(pub_cert), os.path.join(self.links["config_root"], "certdb.sqlite"), self.links)
        
        
    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()
        
cmdanot={
    "help": ("", "open help"),
    "show": ("","general info about client"),
    "setconfig": (" <key>/<value>", "set key of main config to value"),
    "setpluginconfig": (" <plugin>/<key>/<value>", "set key of plugin config to value"),
    "register": (" <serverurl>", "register ip on server"),
    "registerservice": (" [clientname:port/]<servicename>/<serviceport>", "register service on client\n    (server accepts only localhost by default)"),
    "get": (" <serverurl>/<name>/<hash>", "retrieve ip from client from server")

    }
                
def cmdhelp():
    out="""### cmd-commands ###
hash <pw>: calculate hash for pw
plugin <plugin>/<...>: speak with plugin
"""
    for elem in client_client.validactions:
        if elem in client_admin.validactions_admin:
            eperm = "{}(admin)".format(elem)
        else:
            eperm = elem
        if elem in cmdanot:
            out += "{}{}: {}".format(eperm,*cmdanot[elem])+"\n"
        else:
            out += "{}: {}".format(eperm,"<undocumented>")+"\n"

    out += """
### cmd-headers ###
headers defined this way: ...?<header1>=<value1>&<header2>=<value2>...
TODO
"""
    return out
    
def paramhelp():
    return """
### parameters ###
config=<dir>: path to config dir
port=<number>: Port
(c/a/s)pwhash=<hash>: sha256 hash of pw, higher preference than pwfile
(c/a/s)pwfile=<file>: file with password (cleartext)
remote: remote reachable (not localhost) (needs cpwhash/file)
priority=<number>: set priority
timeout=<number>: socket timeout
webgui: enables webgui
cmd: opens cmd
c: set password for using client webcontrol
a: set password for using client webcontrol admin panel
s: set password for contacting client
"""
    
def signal_handler(_signal, frame):
  sys.exit(0)


#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args={"noplugins": None,
             "cpwhash": None,
             "cpwfile": None,
             "apwhash": None,
             "apwfile": None,
             "spwhash": None,
             "spwfile": None,
             "remote": None,
             "priority": "20",
             "timeout": "30",
             "webgui": None,
             "cmd": None}
             
client_args={"config":default_configdir,
             "port":None}

if __name__ ==  "__main__":    
    from common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    
    pluginpathes=[os.path.join(sharedir, "plugins")]
    
    if len(sys.argv) > 1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help","h"]:
                print(paramhelp())
                sys.exit(0)
            else:
                tparam=elem.split("=")
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    client_args[tparam[0]] = "True"
                    continue
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1], ]
                    continue
                client_args[tparam[0]] = tparam[1]

    configpath=client_args["config"]
    configpath=path.expanduser(configpath)
    if configpath[-1]==os.sep:
        configpath=configpath[:-1]
    client_args["config"]=configpath
    # path  to plugins in config folder
    pluginpathes.insert(1,os.path.join(configpath, "plugins"))
    
    # path to config folder of plugins
    configpath_plugins=os.path.join(configpath, "config", "plugins")
    #if configpath[:-1]==os.sep:
    #    configpath=configpath[:-1]
    
    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    confm = configmanager(os.path.join(configpath, "config", "clientmain{}".format(confdb_ending)))
    confm.update(default_client_args,client_args)

    if confm.getb("noplugins")==False:
        pluginm=pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui")!=False:
            pluginm.interfaces+=["web",]
        if confm.getb("cmd")!=False:
            pluginm.interfaces+=["cmd",]
    else:
        pluginm=None

    cm=client_init(confm,pluginm)

    if confm.getb("noplugins")==False:
        # needs not much as ressource (interfaces)
        pluginm.resources["access"] = cm.links["client"].access_safe
        pluginm.init_plugins()

    if confm.getb("cmd")!=False:
        logger().debug("start client server")
        cm.serve_forever_nonblock()
        logger().debug("start console")
        print(*cm.links["client"].show()[1],sep="/")
        while True:
            inp=input("Enter command, seperate by \"/\"\nEnter headers by closing command with \"?\" and\nadding key1=value1&key2=value2 key/value pairs:\n")
            if inp in ["exit", "close", "quit"]:
                break
            ret=cm.links["client"].command(inp)
            if ret[1] is not None:
                if ret[0] == True:
                    if ret[2] == isself:
                        print("This client:")
                    else:
                        print("{} with hash:\n {}\n answers:".format(ret[2], ret[3]))
                print(ret[1])
    else:
        logger().debug("start client server")
        cm.serve_forever_block()

