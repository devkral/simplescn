#! /usr/bin/env python3

import sys, os
import socket

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


from client_admin import client_admin, is_admin_func
from client_safe import client_safe
from client_config import client_config

from http.server  import BaseHTTPRequestHandler,HTTPServer
from http import client
import socketserver
import logging
import ssl
import signal,threading
import json
import time
from os import path
from urllib import parse

from common import check_certs, generate_certs, init_config_folder, default_configdir, certhash_db, default_sslcont, dhash, VALNameError, VALHashError, isself, check_name, commonscn, scnparse_url, AddressFail, pluginmanager, configmanager, pwcallmethod, rw_socket, notify, confdb_ending, check_args, safe_mdecode, generate_error, max_serverrequest_size, gen_result, check_result, check_argsdeco, scnauth_server, generate_error_deco, VALError, client_port, default_priority, default_timeout, check_hash
#VALMITMError

from common import logger

def open_pwcall_plugin(msg, requester=None):
    pwcallmethod("{}: {}".format(requester, msg))()

def open_notify_plugin(msg, requester=None):
    notify("{}: {}".format(requester, msg))

reference_header = \
{
"User-Agent": "simplescn/0.5 (client)",
"Authorization": 'scn {}', 
"Connection": 'keep-alive'
}
class client_client(client_admin, client_safe, client_config):
    name = None
    cert_hash = None
    sslcont = None
    hashdb = None
    links = None
    redirect_addr = None
    redirect_hash = None
    #brokencerts = []
    # client_lock = None
    validactions = {"cmd_plugin", "remember_auth" }
    
    def __init__(self, _name, _pub_cert_hash, _certdbpath, certfpath, _links):
        client_admin.__init__(self)
        client_safe.__init__(self)
        client_config.__init__(self)
        # self.client_lock = threading.RLock()
        self.links = _links
        self.name = _name
        self.cert_hash = _pub_cert_hash
        self.hashdb = certhash_db(_certdbpath)
        self.sslcont = self.links["hserver"].sslcont #default_sslcont()
        
        if "hserver" in self.links:
            
            self.udpsrcsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.udpsrcsock.bind(self.links["hserver"].socket.getsockname())
        
        for elem in os.listdir(os.path.join(self.links["config_root"], "broken")):
            _splitted = elem.rsplit(".", 1)
            if _splitted[1] != "reason":
                continue
            _hash = _splitted[0]
            with open(os.path.join(self.links["config_root"], "broken", elem), "r") as reado:
                _reason = reado.read().strip().rstrip()
            if check_hash(_hash) and (_hash, _reason) not in self.brokencerts:
                self.brokencerts.append((_hash, _reason))
                
        #self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv")
        # update self.validactions
        self.validactions.update(client_admin.validactions_admin)
        self.validactions.update(client_safe.validactions_safe)
        self.validactions.update(client_config.validactions_config)
        self._cache_help = self.cmdhelp()
    
    def pw_auth(self, hashpcert, reqob, reauthcount):
        if reauthcount == 0:
            authob = self.links["auth"].reauth(hashpcert, reqob)
        else:
            authob = None
        if reauthcount <= 3:
            authob = self.links["auth"].auth(pwcallmethod("Please enter password for {}:\n".format(reqob["realm"]))(), reqob, hashpcert)
        return authob

    def do_request(self, _addr_or_con, _path, body={}, headers=None, forceport=False, clientforcehash=None, forcetraverse=False, sendclientcert=False, _reauthcount=0, _certtupel=None):
        if headers is None:
            headers = body.pop("headers", {})
        else:
            body.pop("headers", {})
        
        sendheaders = reference_header.copy()
        for key,value in headers.items():
            if key in ["Connection", "Host", "Accept-Encoding", "Content-Type", "Content-Length", "User-Agent", "X-certrewrap"]:
                continue
            key, value = elem
            sendheaders[key] = value
        
        sendheaders["Content-Type"] = "application/json; charset=utf-8"
        if sendclientcert:
            sendheaders["X-certrewrap"] = self.cert_hash
        
        if isinstance(_addr_or_con, client.HTTPSConnection) == False:
            _addr = scnparse_url(_addr_or_con,force_port=forceport)
            con = client.HTTPSConnection(_addr[0], _addr[1], context=self.sslcont)
            try:
                con.connect()
            except ConnectionRefusedError:
                forcetraverse = True
            
            if forcetraverse:
                _tsaddr = scnparse_url(body.get("traverseserveraddr"))
                contrav = client.HTTPSConnection(_tsaddr[0], _tsaddr[1], context=self.sslcont)
                contrav.connect()
                _sport = contrav.sock.getsockname()[1]
                retserv = self.do_request(contrav, "/server/open_traversal")
                contrav.close()
                if retserv[0]:
                    con.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    con.sock.bind(('', _sport))#retserv.get("traverse_address"))
                    for count in range(0,3):
                        try:
                            con.sock.connect((_addr[0], _addr[1]))
                            break
                        except Exception:
                            pass
                    con.sock = self.sslcont.wrap_socket(con.sock)
        else:
            con = _addr_or_con
            #if headers.get("Connection", "") != "keep-alive":
            #    con.connect()
        
        if _certtupel is None:
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
            hashpcert = dhash(pcert)
            if clientforcehash is not None:
                if clientforcehash != hashpcert:
                    raise(VALHashError)
            elif body.get("forcehash") is not None:
                if body.get("forcehash") != hashpcert:
                    raise(VALHashError)
            if hashpcert == self.cert_hash:
                validated_name = isself
            else:
                hashob = self.hashdb.get(hashpcert)
                if hashob:
                    validated_name = (hashob[0],hashob[3])
                    if validated_name == isself:
                        raise(VALNameError)
                else:
                    validated_name = None
            _certtupel = (validated_name, hashpcert)
            
        #start connection
        con.putrequest("POST", _path)
        for key, value in sendheaders.items():
            #if key != "Proxy-Authorization":
            con.putheader(key, value)
        pwcallm = body.get("pwcall_method")
        if pwcallm:
            del body["pwcall_method"]
        ob = bytes(json.dumps(body), "utf-8")
        con.putheader("Content-Length", str(len(ob)))
        con.endheaders()
        if sendclientcert:
            #con.sock = con.sock.unwrap()
            con.sock = self.sslcont.wrap_socket(con.sock, server_side=True)
        con.send(ob)
        
        response = con.getresponse()
        servertype = response.headers.get("Server", "")
        logger().debug("Servertype: {}".format(servertype))
        if response.status == 401:
            body["pwcall_method"] = pwcallm
            auth_parsed = json.loads(sendheaders.get("Authorization", "scn {}").split(" ")[1])
            if response.headers.get("Content-Length", "").strip().rstrip().isdigit() == False:
                con.close()
                return False, "no content length", _certtupel[0], _certtupel[1]
            readob = response.read(int(response.headers.get("Content-Length")))
            reqob = safe_mdecode(readob, response.headers.get("Content-Type","application/json; charset=utf-8"))
            if reqob is None:
                con.close()
                return False, "Invalid Authorization request object", _certtupel[0], _certtupel[1]
            realm = reqob.get("realm")
            if callable(pwcallm) == True:
                authob = pwcallm(hashpcert, reqob, _reauthcount)
            else:
                authob = None

            if authob is None:
                con.close()
                return False, "Authorization object invalid", _certtupel[0], _certtupel[1]
            _reauthcount += 1
            auth_parsed[realm] = authob
            sendheaders["Authorization"] = "scn {}".format(json.dumps(auth_parsed))
            return self.do_request(con, _path, body=body, clientforcehash=clientforcehash, headers=sendheaders, forceport=forceport, _certtupel=_certtupel, forcetraverse=forcetraverse, traverseserveraddr=traverseserveraddr, _reauthcount=_reauthcount)
        else:
            if response.headers.get("Content-Length", "").strip().rstrip().isdigit() == False:
                con.close()
                return False, "No content length", _certtupel[0], _certtupel[1]
            readob = response.read(int(response.getheader("Content-Length")))
            
            # kill keep-alive connection when finished, or transport connnection
            #if isinstance(_addr_or_con, client.HTTPSConnection) == False:
            con.close()
            if response.status == 200:
                status = True
            else:
                status = False
            
            if response.headers.get("Content-Type").split(";")[0].strip().rstrip() in ["text/plain","text/html"]:
                obdict = gen_result(str(readob, "utf-8"), status)
            else:
                obdict = safe_mdecode(readob, response.headers.get("Content-Type", "application/json"))
            if check_result(obdict, status) == False:
                return False, "error parsing request\n{}".format(readob), _certtupel[0], _certtupel[1]
            
            if status == True:
                return status, obdict["result"], _certtupel[0], _certtupel[1]
            else:
                return status, obdict["error"], _certtupel[0], _certtupel[1]
    
    def use_plugin(self, address, plugin, paction, forcehash=None,originalcert=None,  forceport=False, requester=None):
        _addr = scnparse_url(address, force_port=forceport)
        con = client.HTTPSConnection(_addr[0], _addr[1], context=self.sslcont)
        con.putrequest("POST", "/plugin/{}/{}".format(plugin, paction))
        con.putheader("X-certrewrap", self.cert_hash)
        con.putheader("User-Agent", "simplescn/0.5 (client-plugin)")
        if originalcert:
            con.putheader("X-original_cert", originalcert)
        con.endheaders()
        sock = con.sock
        con.sock = None
        cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True)).strip().rstrip()
        _hash = dhash(cert)
        if _hash != forcehash:
            sock.close()
            return None, cert, _hash
        #sock = sock.unwrap()
        sock = self.sslcont.wrap_socket(sock, server_side=True)
        return sock, cert, _hash
        
    @check_argsdeco({"plugin": (str, "name of plugin"), "paction": (str, "action of plugin")})
    def cmd_plugin(self, obdict):
        """ trigger commandline action of plugin """ 
        plugins = self.links["client_server"].pluginmanager.plugins
        if plugins is None:
            return False, "no plugins loaded"
        if obdict["plugin"] not in plugins:
            ret[0] = False
            ret[1] = "Error: plugin does not exist"
            return False, "Error: plugin does not exist"
        plugin = plugins[obdict["plugin"]]
        if hasattr(plugin, "cmd_node_actions") == False:
            return False,  "Error: plugin does not support commandline"
                
        action = obdict["paction"]
        if hasattr(plugin, "cmd_node_localized_actions") and \
                action in plugin.cmd_node_localized_actions:
                action = plugin.cmd_node_localized_actions[action]
        try:
            resp = plugin.cmd_node_actions[action][0](obdict)
            return True, resp
        except Exception as e:
            False, generate_error(e)
    
    # auth is special variable see safe_mdecode in common
    @check_argsdeco({"auth": (dict, ), "hash": (str, ), "address": (str, )})
    def remember_auth(self, obdict):
        """ Remember Authentification info for as long the program runs """
        if obdict.get("hash") is None:
            _hashob = self.gethash(obdict)
            if _hashob[0] == False:
                return False, "invalid address for retrieving hash"
            _hash = _hashob[1]["hash"]
        else:
            _hash = obdict.get("hash")
        for realm, pw in obdict.get("auth"):
            self.links["auth"].saveauth(realm, pw, _hash)
        return True
        
    
    
    # NEVER include in validactions
    # headers=headers
    # client_address=client_address
    def access_core(self, action, obdict):
        """ internal method to access functions """
        if action in self.access_methods:
            return False, "actions: 'access_methods not allowed in access_core", isself, self.cert_hash
        if action in self.validactions:
            #with self.client_lock: # not needed, use sqlite's intern locking mechanic
            try:
                return getattr(self, action)(obdict)
            except Exception as e:
                return False, e #.with_traceback(sys.last_traceback)
        else:
            return False, "not in validactions", isself, self.cert_hash
    
    access_methods = ["access_main", "access_safe", "access_core"]
    # command wrapper for cmd interfaces
    @generate_error_deco
    def command(self, inp):
        obdict = parse.parse_qs(inp)
        error=[]
        if check_args(obdict, {"action": (str, "main action"),},error=error) == False:
            return False, "{}:{}".format(*error)
            #return False, "no action given", isself, self.cert_hash
        if obdict["action"] in ["command"] or obdict["action"] in self.access_methods:
            return False, "actions: 'access_methods, command' not allowed in command"
        action = obdict["action"]
        del obdict["action"]
        def pw_auth_command(pwcerthash, authreqob, reauthcount):
            authob = self.links["auth"].asauth(obdict.get("auth", {}).get(authreqob.get("realm")), authreqob)
            return authob
        obdict["pwcall_method"] = pw_auth_command
        try:
            return self.access_core(action, obdict)
        except Exception as e:
            return False, e
        
    # NEVER include in validactions
    # for plugins, e.g. untrusted
    # requester = None, don't allow asking
    # headers=headers
    # client_address=client_address
    @generate_error_deco
    def access_safe(self, action, requester=None, **obdict):
        if action in ["cmd_plugin",] or action in self.access_methods:
            return False, "actions: 'access_methods, cmd_plugin' not allowed in access_safe"
        def pw_auth_plugin(pwcerthash, authreqob, reauthcount):
            authob = self.links["auth"].asauth(obdict.get("auth", {}).get(authreqob.get("realm")), authreqob)
            return authob
        obdict["pwcall_method"] = pw_auth_plugin
        if action in self.validactions:
            if action in self.validactions_config:
                return False, "{} tried to use protected config methods".format(requester)
            if is_admin_func(action):
                if requester is None or notify('"{}" wants admin permissions\nAllow(y/n)?: '.format(requester)):
                    return False, "no permission"
            return self.access_core(action, obdict)
        else:
            return False, "not in validactions"
    
    
    # NEVER include in validactions
    # for user interactions
    # headers=headers
    # client_address=client_address
    @generate_error_deco
    def access_main(self, action, **obdict):
        obdict["pwcall_method"] = self.pw_auth
        try:
            return self.access_core(action, obdict)
        except Exception as e:
            return False, e
        
    
    # help section
    def cmdhelp(self):
        out="""### cmd-commands ###
hash <pw>: calculate hash for pw
plugin <plugin>:<...>: speak with plugin
"""
        for funcname in sorted(self.validactions):
            if is_admin_func(funcname):
                eperm = " (admin)"
            else:
                eperm = ""
            func = getattr(self, funcname)
            out+="{func}{admin}:{doku}".format(func=funcname, admin=eperm, doku=func.__doc__)
            if hasattr(func, "requires") == False or hasattr(func, "optional") == False:
                print("skip non decorated function: "+funcname)
                continue
            try:
                if len(func.requires) == 0:
                    # xx gets deleted [:-2]
                    out+="\n reqargs: n.a.xx"
                else:
                    out+="\n reqargs: "
                for name, val in func.requires.items():
                    if len(val) == 2:
                        _type, doc = val
                        doc = ":{}".format(doc)
                    elif len(val) == 1:
                        _type = val[0]
                        doc = ""
                    else:
                        print(funcname, "invalid element: ", val)
                        continue
                    out+="{} ({}){}, ".format(name, _type.__name__, doc)
                out=out[:-2]
                if len(func.optional) == 0:
                    # xx gets deleted [:-2]
                    out+="\n optargs: n.a.xx"
                else:
                    out+="\n optargs: "
                for name, val in func.optional.items():
                    if len(val) == 2:
                        _type, doc = val
                        doc = ": {}".format(doc)
                    elif len(val) == 1:
                        _type = val[0]
                        doc = ""
                    else:
                        print(funcname, "invalid element: ", val)
                        continue
                    out+="{} ({}){}, ".format(name, _type.__name__, doc)
                out=out[:-2]
                out+="\n"
            except Exception as e:
                print("Function : \""+funcname+"\" has broken check_argdeco arguments")
                raise(e)
        return out


### receiverpart of client ###

class client_server(commonscn):
    capabilities = ["basic",]
    scn_type = "client"
    spmap = {}
    validactions = {"info", "getservice", "dumpservices", "cap", "prioty", "registerservice", "delservice"}
    local_client_service_control = False
    wlock = None
    def __init__(self, dcserver):
        commonscn.__init__(self)
        self.wlock = threading.Lock()
        if dcserver["name"] is None or len(dcserver["name"]) == 0:
            logger().info("Name empty")
            dcserver["name"] = "<noname>"

        if dcserver["message"] is None or len(dcserver["message"]) == 0:
            logger().info("Message empty")
            dcserver["message"] = "<empty>"
            
        self.name = dcserver["name"]
        self.message = dcserver["message"]
        self.priority = dcserver["priority"]
        self.cert_hash = dcserver["certhash"]
        self.cache["dumpservices"] = json.dumps(gen_result({}, True))
        self.update_cache()
    ### the primary way to add or remove a service
    ### can be called by every application on same client
    ### don't annote list with "map" dict structure on serverside (overhead)
    @check_argsdeco({"name": (str,), "port": (int,)})
    def registerservice(self, obdict):
        """ register a service = (map port to name) """
        if obdict.get("clientaddress") is None:
            False, "bug: clientaddress is None"
        if obdict.get("clientaddress")[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            self.spmap[obdict.get("name")] = obdict.get("port")
            self.cache["dumpservices"] = json.dumps(gen_result(self.spmap, True))
            #self.cache["listservices"] = json.dumps(gen_result(sorted(self.spmap.items(), key=lambda t: t[0]), True))
            self.wlock.release()
            return True
        return False, "no permission"
    
    ### don't annote list with "map" dict structure on serverside (overhead)
    @check_argsdeco({"name": (str, )})
    def delservice(self, obdict):
        """ delete a service"""
        if obdict.get("clientaddress") is None:
            False, "bug: clientaddress is None"
        if obdict.get("clientaddress")[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            if obdict["name"] in self.spmap:
                del self.spmap[obdict["name"]]
                self.cache["dumpservices"] = json.dumps(gen_result(self.spmap, True)) #sorted(self.spmap.items(), key=lambda t: t[0]), True))
            self.wlock.release()
            return  True
        return False, "no permission"
        
    ### management section - end ###
    @check_argsdeco({"name":(str,)})
    def getservice(self, obdict):
        """ get the port of a service """
        if obdict["name"] not in self.spmap:
            return False
        return True, self.spmap[obdict["name"]]
    
    
class client_handler(BaseHTTPRequestHandler):
    server_version = 'simplescn/0.5 (client)'
    sys_version = "" # would say python xy, no need and maybe security hole
    auth_info = None
    
    client_certhash = None
    links = None
    handle_local = False
    # overwrite handle_local
    handle_remote = False
    statics = {}
    webgui = False
    
    def scn_send_answer(self, status, ob, _type="application/json"):
        self.send_response(status)
        self.send_header("Content-Length", len(ob))
        self.send_header("Content-Type", "{}; charset=utf-8".format(_type))
        self.end_headers()
        self.wfile.write(ob)
    
    def html(self, page, lang = "en"):
        if self.webgui == False:
            self.send_error(404, "no webgui")
            return
        _ppath = os.path.join(sharedir, "html", lang, page)
        fullob = None
        with open(_ppath, "rb") as rob:
            fullob = rob.read()
        if fullob is None:
            self.send_error(404, "file not found")
        else:
            self.scn_send_answer(200, fullob, "text/html")

    def handle_client(self, action):
        if action not in self.links["client"].validactions:
            self.send_error(400, "invalid action - client")
            return
        if self.handle_remote == False and (self.handle_local == False \
                and not self.client_address2[0] in ["localhost", "127.0.0.1", "::1"]):
            self.send_error(403, "no permission - client")
            return
        
        if is_admin_func(action):
            #if self.client_cert is None:
            #    self.send_error(403, "no permission (no certrewrap) - admin")
            #    return
            if "admin" in self.links["auth"].realms:
                realm = "admin"
            else:
                realm = "client"
        else:
            realm = "client"
        if self.links["auth"].verify(realm, self.auth_info) == False:
            authreq = self.links["auth"].request_auth(realm)
            ob = bytes(json.dumps(authreq), "utf-8")
            self.scn_send_answer(401, ob)
            return
        
        if self.headers.get("Content-Length", "").strip().rstrip().isdecimal() == False:
            self.send_error(411,"POST data+data length needed")
            return
        readob = self.rfile.read(int(self.headers.get("Content-Length")))
        # str: charset (like utf-8), safe_mdecode: transform arguments to dict
        obdict = safe_mdecode(readob, self.headers.get("Content-Type"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        obdict["clientaddress"] = self.client_address2
        obdict["clientcert"] = self.client_cert
        obdict["headers"] = self.headers
        response = self.links["client"].access_core(action, obdict)

        if response[0] == False:
            error = response[1]
            generror = generate_error(error)
                
            if isinstance(error, (str, AddressFail, VALError)):
                if isinstance(error, str) == False:
                    del generror["stacktrace"]
                jsonnized = json.dumps(gen_result(generror, False))
            else:
                if self.client_address2[0] not in ["localhost", "127.0.0.1", "::1"]:
                    generror = generate_error("unknown")
                ob = bytes(json.dumps(gen_result(generror, False)), "utf-8")
                self.scn_send_answer(500, ob)
                return
        else:
            jsonnized = json.dumps(gen_result(response[1],response[0]))
        
        if response[0] == False:
            self.send_response(400)
        else:
            self.send_response(200)
        
        ob=bytes(jsonnized, "utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header('Content-Type', "application/json; charset=utf-8")
        self.send_header('Content-Length', str(len(ob)))
        self.end_headers()
        self.wfile.write(ob)

    def handle_server(self, action):
        if action not in self.links["client_server"].validactions:
            self.send_error(400, "invalid action - server")
            return
        
        if self.links["auth"].verify("server", self.auth_info) == False:
            authreq = self.links["auth"].request_auth("server")
            ob = bytes(json.dumps(authreq), "utf-8")
            self.scn_send_answer(401, ob)
            return
        
        if action in self.links["client_server"].cache:
            ob = bytes(self.links["client_server"].cache[action], "utf-8")
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
        obdict = safe_mdecode(readob,self.headers.get("Content-Type", "application/json; charset=utf-8"))
        if obdict is None:
            self.send_error(400, "bad arguments")
            return
        obdict["clientaddress"] = self.client_address2
        obdict["clientcert"] = self.client_cert
        obdict["headers"] = self.headers
        try:
            func = getattr(self.links["client_server"], action)
            response = func(obdict)
            jsonnized = json.dumps(gen_result(response[1],response[0]))
        except Exception as e:
            error = generate_error("unknown")
            if self.client_address2[0] in ["localhost", "127.0.0.1", "::1"]:
                error = generate_error(e)
            ob = bytes(json.dumps(gen_result(error, False)), "utf-8")
            self.scn_send_answer(500, ob)
            return
        
        
        if jsonnized is None:
            jsonnized = json.dumps(gen_result(generate_error("jsonnized None"), False))
            response[0] = False
        if response[0] == False:
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
                return
        # for e.g. GET stuck jabber server
        #elif  _path[0]=="service" and len(_path)==2:
        #    ret = self.links["client_server"].get(_path[1])
        #    if ret[0]:
        #        self.send_response(307)
        #        self.end_headers()
                #self.wfile.write(self.statics[_path[1]])
        #        return
        
        elif len(_path)==2:
            self.handle_server(_path[0])
            return
        self.send_error(404, "not -found")
    
    def init_scn_stuff(self):
        useragent = self.headers.get("User-Agent", "")
        logger().debug("Useragent: {}".format(useragent))
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
        
        if self.client_address[0][:7] == "::ffff:":
            self.client_address2 = (self.client_address[0][7:], self.client_address[1])
        else:
            self.client_address2 = (self.client_address[0], self.client_address[1])
        
        # hack around not transmitted client cert
        _rewrapcert = self.headers.get("X-certrewrap")
        _origcert = self.headers.get("X-original_cert")
        if _rewrapcert is not None:
            cont = self.connection.context
            #self.connection = self.connection.unwrap()
            self.connection = cont.wrap_socket(self.connection, server_side=False)
            self.client_cert = ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True)).strip().rstrip()
            if _rewrapcert != dhash(self.client_cert):
                return False
            if _origcert:
                if _rewrapcert == self.links.get("trusted_certhash"):
                    self.client_cert = _origcert
                else:
                    logger().debug("rewrapcert incorrect")
                    return False
            #self.rfile.close()
            #self.wfile.close()
            self.rfile = self.connection.makefile(mode='rb')
            self.wfile = self.connection.makefile(mode='wb')
        else:
            self.client_cert = None
        return True

    def do_POST(self):
        if self.init_scn_stuff() == False:
            return
        splitted = self.path[1:].split("/", 1)
        if len(splitted) == 1:
            resource = splitted[0]
            sub = ""
        else:
            resource = splitted[0]
            sub = splitted[1]
        
        if resource == "plugin":
            pluginm = self.links["client_server"].pluginmanager
            split2 = sub.split("/", 1)
            if len(split2) != 2:
                self.send_error(400, "no plugin/action specified", "No plugin/action was specified")
                return
            plugin, action = split2
            
            if plugin not in pluginm.plugins:
                self.send_error(404, "plugin not available", "Plugin with name {} does not exist".format(sub))
                return

            
            # gui receive
            if hasattr(pluginm.plugins[plugin], "receive") == True:
                # not supported yet
                # don't forget redirect_hash
                if self.links["client"].redirect_addr not in ["", None]:
                    if hasattr(pluginm.plugins[plugin], "rreceive") == True:
                        try:
                            ret = pluginm.plugins[plugin].rreceive(action, self.connection, self.client_cert, dhash(self.client_cert))
                        except Exception as e:
                            logger().error(e)
                            self.send_error(500, "plugin error", str(e))
                            ret = False
                    else:
                        ret = True
                    if ret == False:
                        return
                    sockd = self.links["client"].use_plugin(self.links["client"].redirect_addr, \
                                        plugin, action, forcehash=self.links["client"].redirect_hash, originalcert=self.client_cert)
                    redout = threading.Thread(target=rw_socket, args=(self.connection, sockd), daemon=True)
                    redout.run()
                    rw_socket(sockd, self.connection)
                    return
                else:
                    try:
                        pluginm.plugins[plugin].receive(action, self.connection, self.client_cert, dhash(self.client_cert))
                    except Exception as e:
                        logger().error(e)
                        self.send_error(500, "plugin error", str(e))
                        return
        # for invalidating and updating, DON'T USE connection afterward
        elif resource == "usebroken":
            cont = default_sslcont()
            certfpath = os.path.join(self.links["config_root"], "broken", sub)
            if os.path.isfile(certfpath+".pub") and os.path.isfile(certfpath+".priv"):
                cont.load_cert_chain(certfpath+".pub", certfpath+".priv")
                #self.end_headers()
                
                oldsslcont = self.connection.context
                
                #self.connection = self.connection.unwrap()
                self.connection = cont.wrap_socket(self.connection, server_side=True)
                #self.connection.getpeercert() # handshake
                time.sleep(1) # better solution needed
                self.connection = self.connection.unwrap()
                #self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile(mode='rb')
                self.wfile = self.connection.makefile(mode='wb')
                
                #self.wfile.write(b"test")
                self.send_response(200, "broken cert test")
                self.end_headers()
                
            else:
                oldsslcont = self.connection.context
                #self.connection = self.connection.unwrap()
                self.connection = oldsslcont.wrap_socket(self.connection, server_side=True)
                #time.sleep(1) self.connection.getpeercert() # handshake
                self.connection = self.connection.unwrap()
                self.rfile = self.connection.makefile(mode='rb')
                self.wfile = self.connection.makefile(mode='wb')
                self.send_error(404, "broken cert not found")
        elif resource == "server":
            self.handle_server(sub)
        elif resource == "client":
            self.handle_client(sub)
        else:
            self.send_error(404, "resource not found", "could not find {}".format(resource))
        
class http_client_server(socketserver.ThreadingMixIn,HTTPServer):
    """server part of client; inheritates client_server to provide
        client information"""
    sslcont = None
    rawsock = None
    
    def __init__(self, _client_address, certfpath, address_family):
        self.address_family = address_family
        HTTPServer.__init__(self, _client_address, client_handler, False)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise
        self.sslcont = default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub", certfpath+".priv")
        self.rawsock = self.socket
        self.socket = self.sslcont.wrap_socket(self.socket)

    #def get_request(self):
    #    if self.socket is None:
    #        return None, None
    #    socketserver.TCPServer.get_request(self)

class client_init(object):
    config_root = None
    plugins_config = None
    links = None
    
    def __init__(self,confm,pluginm):
        self.links = {}
        self.links["config"] = confm
        self.links["config_root"] = confm.get("config")
        
        _cpath=os.path.join(self.links["config_root"],"client")
        init_config_folder(self.links["config_root"],"client")
        
        
        if check_certs(_cpath+"_cert") == False:
            logger().info("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logger().info("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip() #why fail
        
        self.links["auth"] = scnauth_server(dhash(pub_cert))
        
        if confm.getb("webgui")!=False:
            logger().debug("webgui enabled")
            client_handler.webgui=True
            #load static files
            for elem in os.listdir(os.path.join(sharedir, "static")):
                with open(os.path.join(sharedir,"static",elem), 'rb') as _staticr:
                    client_handler.statics[elem]=_staticr.read()
        else:
            client_handler.webgui=False
        
        if confm.getb("local"):
            client_handler.handle_local = True
        if confm.getb("cpwhash") == True:
            # ensure that password is set when allowing remote
            if confm.getb("remote") == True and confm.getb("local") == False:
                client_handler.handle_remote = True
            self.links["auth"].init_realm("client", confm.get("cpwhash"))
        elif confm.getb("cpwfile") == True:
            # ensure that password is set when allowing remote
            if confm.getb("remote") == True:
                client_handler.handle_remote = True
            op=open(confm.get("cpwfile"), "r")
            pw = op.readline().strip().rstrip()
            self.links["auth"].init_realm("client", dhash(pw))
            op.close()
        
        if confm.getb("apwhash") == True:
            self.links["auth"].init_realm("admin", confm.get("apwhash"))
        elif confm.getb("apwfile") == True:
            op = open(confm.get("apwfile"), "r")
            pw = op.readline().strip().rstrip()
            self.links["auth"].init_realm("admin", dhash(pw))
            op.close()
            
        if confm.getb("spwhash") == True:
            self.links["auth"].init_realm("server", confm.get("spwhash"))
        elif confm.getb("spwfile") == True:
            op = open(confm.get("spwfile"), "r")
            pw = op.readline().strip().rstrip()
            self.links["auth"].init_realm("server", confm.get(dhash(pw)))
            op.close()
        

        with open(_cpath+"_name.txt", 'r') as readclient:
            _name = readclient.readline().strip().rstrip() # remove \n
            
        with open(_cpath+"_message.txt", 'r') as readinmes:
            _message = readinmes.read()
        #report missing file
        if None in [pub_cert, _name, _message]:
            raise(Exception("missing"))
        
        _name = _name.split("/")
        if len(_name)>2 or check_name(_name[0]) == False:
            logger().error("Configuration error in {}\nshould be: <name>/<port>\nor name contains some restricted characters".format(_cpath+"_name"))
            sys.exit(1)

        if confm.getb("port") == True:
            pass
        elif len(_name) >= 2:
            confm.set("port", _name[1])
        else: # fallback
            confm.set("port", str(client_port))
        port = confm.get("port")
        
        clientserverdict={"name": _name[0], "certhash": dhash(pub_cert),
                "priority": confm.get("priority"), "message": _message}
        
        self.links["client_server"] = client_server(clientserverdict)
        self.links["client_server"].pluginmanager = pluginm
        self.links["configmanager"] = confm
        

        client_handler.links = self.links
        
        # use timeout argument of BaseServer
        http_client_server.timeout = confm.get("timeout")
        if confm.getb("noserver") == False:
            self.links["hserver"] = http_client_server(("", port), _cpath+"_cert", socket.AF_INET6)
        self.links["client"] = client_client(_name[0], dhash(pub_cert), os.path.join(self.links["config_root"], "certdb.sqlite"), _cpath+"_cert", self.links)
        
        
    def serve_forever_block(self):
        self.links["hserver"].serve_forever()
        
    def serve_forever_nonblock(self):
        sthread = threading.Thread(target=self.serve_forever_block, daemon=True)
        sthread.start()
        

def paramhelp():
    t = "### parameters (permanent) ###\n"
    for _key, elem in sorted(default_client_args.items(), key=lambda x: x[0]):
        t += _key+":"+elem[0]+":"+elem[2]+"\n"
    t += "### parameters (non-permanent) ###\n"
    for _key, elem in sorted(client_args.items(), key=lambda x: x[0]):
        t += _key+":"+elem[0]+":"+elem[2]+"\n"
    return t
    
def signal_handler(_signal, frame):
  sys.exit(0)


#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args={"noplugins": ["False", bool, "deactivate plugins"],
             "cpwhash": ["", str, "<hash>: sha256 hash of pw, higher preference than pwfile"],
             "cpwfile": ["", str, "<file>: file with password (cleartext)"],
             "apwhash": ["", str, "<hash>: sha256 hash of pw, higher preference than pwfile"],
             "apwfile": ["", str, "<file>: file with password (cleartext)"],
             "spwhash": ["", str, "<hash>: sha256 hash of pw, higher preference than pwfile"],
             "spwfile": ["", str, "<file>: file with password (cleartext)"],
             "noserver": ["False", bool, "deactivate server component"],
             "local" : ["False", bool, "reachable from localhost (overwrites remote)"],
             "remote" : ["False", bool, "remote reachable (not localhost) (needs cpwhash/file)"],
             "priority": [str(default_priority), int, "<number>: set priority"],
             "timeout": [str(default_timeout), int, "<number>: set priority"],
             "webgui": ["False", bool, "enables webgui"],
             "cmd": ["False", bool, "enables cmd"]}
             
client_args={"config": [default_configdir, str, "<dir>: path to config dir"],
             "port": [str(client_port), int, "<number>: Port"]}

if __name__ ==  "__main__":
    from common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    
    pluginpathes = [os.path.join(sharedir, "plugins")]
    
    if len(sys.argv) > 1:
        tparam = ()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help","h"]:
                print(paramhelp())
                sys.exit(0)
            else:
                tparam = elem.split("=")
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    if tparam[0] not in client_args:
                        client_args[tparam[0]] = ["True"]
                    else:
                        client_args[tparam[0]][0] = "True"
                    continue
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1], ]
                    continue
                if tparam[0] not in client_args:
                    client_args[tparam[0]] = [tparam[1], None]
                else:
                    client_args[tparam[0]][0] = tparam[1]
    
    configpath = client_args["config"][0]
    configpath = path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    client_args["config"][0] = configpath
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    
    # path to config folder of plugins
    configpath_plugins=os.path.join(configpath, "config", "plugins")
    #if configpath[:-1]==os.sep:
    #    configpath=configpath[:-1]
    
    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    
    confm = configmanager(os.path.join(configpath, "config", "clientmain{}".format(confdb_ending)))
    confm.update(default_client_args, client_args)
    if confm.getb("noplugins") == False:
        pluginm=pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        if confm.getb("cmd") != False:
            pluginm.interfaces += ["cmd",]
    else:
        pluginm=None
    cm = client_init(confm,pluginm)

    if confm.getb("noplugins") == False:
        pluginm.resources["plugin"] = cm.links["client"].use_plugin
        pluginm.resources["access"] = cm.links["client"].access_safe
        pluginm.init_plugins()

    logger().debug("start servercomponent (client)")
    if confm.getb("cmd") != False:
        cm.serve_forever_nonblock()
        logger().debug("start console")
        for name, value in cm.links["client"].show({})[1].items():
            print(name, value, sep=":")
        while True:
            inp = input('urlgetformat:\naction=<action>&arg1=<foo>\nuse action=saveauth&auth=<realm>:<pw>&auth=<realm2>:<pw2> to save pws. Enter:\n')
            if inp in ["exit", "close", "quit"]:
                break
            # help
            if inp == "help":
                inp = "action=help"
            ret=cm.links["client"].command(inp)
            if ret[1] is not None:
                if ret[0] == True:
                    print("Success: ", end="")
                else:
                    print("Error: ", end="")
                if ret[2] == isself:
                    print("This client:")
                elif ret[2] == None:
                    print("Unknown partner, hash: {}:".format(ret[3]))
                else:
                    print("Known, name: {} ({}):".format(ret[2][0],ret[2][1]))
                if isinstance(ret[1], dict):
                    for elem in ret[1].items():
                        if isinstance(elem[1], str):
                            print("{}:{}".format(elem[0], elem[1].replace("\\n", "\n")))
                        else:
                            print("{}:{}".format(elem[0], elem[1]))
                else:
                    print(ret[1])
    else:
        cm.serve_forever_block()

