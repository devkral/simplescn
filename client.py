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
import sys,signal,threading
import socket
import json
from os import path

from common import success, error, check_certs, generate_certs, init_config_folder, default_configdir, certhash_db, default_sslcont, parse_response, dhash, VALNameError, VALHashError, isself, check_name, check_hash, dhash_salt, gen_passwd_hash, commonscn, scnparse_url, AddressFail, pluginmanager, configmanager, check_reference, check_reference_type, pwcallmethod


from common import logger


#"tdesthash": None,
#"cpwhash": None,
#"spwhash": None,
#"tpwhash":None,
reference_header = \
{
"certhash": None,
"cpwauth": None,
"apwauth": None,
"spwauth": None,
"tpwauth":None,
"tdestname":None,
"tdesthash": None,
"nonce":None,
"tnonce":None
}
class client_client(client_admin, client_safe):
    name=None
    cert_hash=None
    sslcont=None
    hashdb = None
    links = None
    
    validactions=set()
    validactions_data={"command",}
    #_cache_help = None
    # "access"
    #pwcache={}
    
    def __init__(self, _name, _pub_cert_hash, _certdbpath, _links):
        self.links = _links
        self._cache_help = cmdhelp()
        self.name = _name
        self.cert_hash = _pub_cert_hash # dhash(_pub_cert)
        self.hashdb = certhash_db(_certdbpath)
        #self.sslcont_register = links["server"].sslcont
        self.validactions.update(client_admin.validactions_admin)
        self.validactions.update(client_safe.validactions_safe)
        self._cache_help = cmdhelp()

    def do_request(self, _addr, requeststr, dheader, body=None, forceport=False,requesttype="GET", context=self.sslcont):
        _addr=scnparse_url(_addr,force_port=forceport)
        con=client.HTTPSConnection(_addr[0],_addr[1], context)
        con.connect()
        pcert=ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
        hashpcert=dhash(pcert)
        if hashpcert==self.cert_hash:
            val = isself
        elif dheader["certhash"] is not None and dheader["certhash"]!=hashpcert:
            raise(VALHashError)
        else:
            val=self.hashdb.certhash_as_name(hashpcert)
            if val == isself:
                raise(VALNameError)
        pheaders={}
        for elem in ["spwauth", "apwauth", "cpwauth", "nonce"]:
            if dheader[elem] is not None:
                pheaders[elem] = dheader[elem]

        if dheader["tdestname"] is not None and dheader["tdesthash"] is not None:
            theaders={}
            for elem in ["tpwauth", "tnonce"]:
                if dheader[elem] is not None:
                    theaders[elem] = dheader[elem]

            con.putrequest("CONNECT", "/{}/{}".format(dheader["tdestname"], dheader["tdesthash"]))
            
            con.set_tunnel(requeststr,theaders)
        else:
            con.putrequest(requesttype, requeststr)
            for elem in pheaders.items():
                con.putheader(*elem)
        
        con.endheaders(body)
        
        if requesttype == "POST" and body is None:
            return con.sock
        r=con.getresponse()
        if r.status == 401:
            dheader["nonce"] = os.urandom(10)
            dheader["tnonce"] = os.urandom(10)
            if "server" in r.response:
                dheader["spwauth"]=dhash_salt(dhash(pwcallmethod("Please enter password for server")()), dheader["nonce"])
            if "client" in r.response:
                dheader["cpwauth"]=dhash_salt(dhash(pwcallmethod("Please enter password for client")()), dheader["nonce"])
            if "admin" in r.response:
                dheader["apwauth"]=dhash_salt(dhash(pwcallmethod("Please enter password for admin")()), dheader["nonce"])
            if "proxy" in r.response:
                dheader["tpwauth"]=dhash_salt(dhash(pwcallmethod("Please enter password for proxy")()),dheader["tnonce"])
            else:
                dheader["tnonce"] = None
            return self.do_request(_addr, requeststr, dheader, body=None, forceport=forceport, requesttype=requesttype)
        else:
            resp=parse_response(r)
            con.close()
            return resp[0],resp[1],val,hashpcert

    # command wrapper for cmd interfaces
    def command(self, _data, reqheader=None):
        if type(_data) is str:
            inp = _data
        else:
            inp = str(_data, "utf8")
        if reqheader is None:
            reqheader=reference_header.copy()
        ret = [False, None, self.cert_hash, isself ]
        if inp == "":
            #ret[output] =
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
        
        # call functions in client
        parsed+=[reqheader,]
        if str(parsed[0]) not in self.validactions:
            ret[0] = False
            ret[1] = "Error: Command does not exist/is not public: {}".format(parsed[0])
            return ret
        try:
            func=self.__getattribute__(str(parsed[0]))
            resp=func(*parsed[1:])
            ret[0] = resp[0]
            ret[1] = str(resp[1])
            if resp[0] == True:
                ret[2] = resp[2]
                ret[3] = resp[3]
        except AddressFail as e:
            ret[0] = False
            ret[1] = "Addresserror:\n{}".format(e.msg)
        except Exception as e:
            st="Error: {}\n".format(e)
            if "tb_frame" in e.__dict__:
                st="{}\n{}\n\n".format(st,traceback.format_tb(e))
            st = "{}Errortype: {}\nCommandline: {}".format(st, type(e).__name__, parsed)
            ret[0] = False
            ret[1] = "Error:\n{}".format(st)
        return ret
    
    # for e.g. plugins
    def access(self, func, *args, dheader=None):
        if dheader is None:
            dheader = reference_header.copy()
        if func in self.validactions and func != "access":
            #args2 = list(args)
            #args2.append(dheader)
            #print(args2)
            return self.__getattribute__(func)(*args)
        else:
            return None
    
    def access_data(self, func, _action, _data, dheader):
        if func in self.validactions_data and func != "access_data":
            #args2 = list(args)
            #args2.append(dheader)
            return self.__getattribute__(func)(_data, dheader)
        else:
            return None


###server on client
    
class client_server(commonscn):
    capabilities = ["basic",]
    scn_type = "client"
    spmap = {}
    validactions = {"info", "getservice", "listservices", "cap", "prioty", "registerservice", "delservice"}
    local_client_service_control = False
    wlock = None
    def __init__(self, _name, _priority, _cert_hash, _message):
        self.wlock = threading.Lock()
        if len(_name) == 0:
            logger().debug("Name empty")
            _name = "<noname>"

        if len(_message) == 0:
            logger().debug("Message empty")
            _message = "<empty>"
            
        self.name = _name
        self.message = _message
        self.priority = _priority
        self.cert_hash = _cert_hash
        
        self.update_cache()
    ### the primary way to add or remove a service
    ### can be called by every application on same client, maybe add additional protection
    def registerservice(self, _service, _port, _addr):
        if _addr[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            self.spmap[_service] = _port
            self.wlock.release()
            return True, "registered"
        return False, "no permission"

    def delservice(self, _service, _addr):
        if _addr[0] in ["localhost", "127.0.0.1", "::1"]:
            self.wlock.acquire()
            if _service in self.spmap:
                del self.spmap[_service]
            self.wlock.release()
            return True, "removed"
        return False, "no permission"
        
    ### management section - end ###
    
    def getservice(self, _service):
        if _service not in self.spmap:
            return False, "service"
        return True, self.spmap[_service]

    def listservices(self):
        return True, json.dumps(self.spmap)

    def info(self):
        return True, self.cache["info"]

    def cap(self):
        return True, self.cache["cap"]
    
    def prioty(self):
        return True, self.cache["prioty"]
    
class client_handler(BaseHTTPRequestHandler):
    server_version = 'simple scn client 0.5'
    
    need_address = ["registerservice", "delservice"]
    
    need_dheader = ["register", "get", "getservice", "listservices", "info", \
    "cap", "prioty_direct", "prioty", "check_direct", "check"]
    
    links = None
    handle_remote = False
    cpwhash = None
    apwhash = None
    spwhash = None
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
        self.send_header('Content-type', "text/html")
        self.end_headers()
        with open(_ppath, "rb") as rob:
            self.wfile.write(rob.read())
            #.format(name=self.links["client_server"].name,message=self.links["client_server"].message),"utf8"))

    def check_cpw(self):
        if self.cpwhash is None:
            return True
        if "cpwauth" in self.headers and "nonce" in self.headers:
            if dhash_salt(self.headers["cpwauth"], self.headers["nonce"]) == self.cpwhash:
                return True
        return False
    
    def check_apw(self):
        if self.apwhash is None:
            return True
        if "apwauth" in self.headers and "nonce" in self.headers:
            if dhash_salt(self.headers["apwauth"], self.headers["nonce"]) == self.apwhash:
                return True
        return False

    def check_spw(self):
        if self.spwhash is None:
            return True
        if "spwhash" in self.headers and "nonce" in self.headers:
            if dhash_salt(self.headers["spwhash"],self.headers["nonce"]) == self.spwhash:
                return True
        return False
    
    def needed_auths(self, _list):
        retauth = []
        if "admin" in _list and self.apwhash is not None:
            retauth.append("admin")
        if "client" in _list and self.cpwhash is not None:
            retauth.append("client")
        if "server" in _list and self.spwhash is not None:
            retauth.append("server")
        retstring=""
        for elem in retauth:
            retstring+=", {}".format(elem)
        return retauth, retstring[2:]
    
    ### PUT ###
    def handle_client_put(self, _cmdlist):
        if _cmdlist[0] not in self.links["client"].validactions:
            self.send_error(400, "invalid action - client")
            return
        _cmdlist += [self.headers,]
        if self.handle_remote == False and not self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
            self.send_error(403, "no permission - client")
            return
        
        if self.check_cpw() == False:
            self.send_error(401, self.needed_auth(["client","admin"])[1]) #"no permission - client")
            return
            
        if self.links["client"].validactions_admin:
            if self.check_apw() == False:
                self.send_error(401, self.needed_auth(["admin"])[1]) #"no permission - admin")
                return
        try:
            func = self.links["client"].__getattribute__(_cmdlist[0])
            response = func(*_cmdlist[1:])
        except AddressFail as e:
            self.send_error(500, e.msg)
            return
        except Exception as e:
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st) > 0:
                    self.send_error(500, st)
                else:
                    self.send_error(500, "unknown")
            return
        if response[0] == False:
            #helps against ssl failing about empty string (EOF)
            if len(response) >= 1 and len(response[1]) > 0:
                self.send_error(400, str(response[1]))
            else:
                self.send_error(400, "unknown")
            return
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type', "text")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response), "utf8"))
    
        
    ### GET ###
    def handle_client(self, _cmdlist):
        action = _cmdlist[0]
        _cmdlist = _cmdlist[:1]
        if _cmdlist[0] not in self.links["client"].validactions:
            self.send_error(400, "invalid action - client")
            return
        if self.handle_remote == False and not self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
            self.send_error(403, "no permission - client")
            return
        
        if self.check_cpw() == False:
            self.send_error(401, self.needed_auth(["client","admin"])[1]) #"no permission - client")
            return
            
        if self.links["client"].validactions_admin:
            if self.check_apw() == False:
                self.send_error(401, self.needed_auth(["admin"])[1]) #"no permission - admin")
                return
        if action in self.need_dheader:
            _cmdlist += [self.headers,]
        
        try:
            func = self.links["client"].__getattribute__(action)
            response = func(*_cmdlist)
        except AddressFail as e:
            self.send_error(500, e.msg)
            return
        except Exception as e:
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st) > 0:
                    self.send_error(500, st)
                else:
                    self.send_error(500, "unknown")
            return
        if response[0] == False:
            #helps against ssl failing about empty string (EOF)
            if len(response) >= 1 and len(response[1]) > 0:
                self.send_error(400, str(response[1]))
            else:
                self.send_error(400, "unknown")
            return
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type', "text")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response), "utf8"))

    def handle_server(self, _cmdlist):
        if _cmdlist[0] not in self.links["client_server"].validactions:
            self.send_error(400, "invalid action - server")
            return
        
        # add address to _cmdlist if needed
        if action in self.need_address:
            _cmdlist += [self.client_address,]
        
        if self.check_spw() == False:
            self.send_error(401, self.needed_auth(["server"])[1]) #"no permission - server")
            return
        
        try:
            func = self.links["client_server"].__getattribute__(_cmdlist[0])
            response = func(*_cmdlist[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost", "127.0.0.1", "::1"]:
                st = "{}:{}".format(type(e).__name__, e)
                if "tb_frame" in e.__dict__:
                    st = "{}\n\n{}".format(st, traceback.format_tb(e))
                #helps against ssl failing about empty string (EOF)
                if len(st) > 0:
                    self.send_error(500, st)
                else:
                    self.send_error(500, "unknown")
            else:
                self.send_error(500, "server error")
            return
        
        if response[0] == False:
            #helps against ssl failing about empty string (EOF)
            if len(response) > 1 and len(response[1]) > 0:
                self.send_error(400, response[1])
            else:
                self.send_error(400, "unknown")
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type', "text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(response) > 1 and len(response[1]) > 0:
                self.wfile.write(bytes(response[1], "utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))
            
    def do_GET(self):
        if self.path == "/favicon.ico":
            if "favicon.ico" in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics["favicon.ico"])
            else:
                self.send_error(404)
            return
        
        pos_header = self.path.find("?")
        if pos_header != -1:
            _cmdlist = self.path[1:pos_header].split("/")
            tparam = self.path[pos_header+1:].split("&")
            for elem in tparam:
                elem = elem.split("=")

                if len(elem) == 2:
                    self.headers[elem[0]] = elem[1]
                else:
                    self.send_error(400, "invalid key/value pair\n{}".format(elem))
                    return
        else:
            _cmdlist = self.path[1:].split("/")

        action = _cmdlist[0]

        if action == "do":
            self.handle_client(_cmdlist[1:]) #remove do
            return
        elif action in self.links["client_server"].validactions:
            self.handle_server(_cmdlist)
            return
        if self.webgui == False:
            self.send_error(400, "no webgui")
            return
        #client 
        if action in ("", "client", "html", "index"):
            self.html("client.html")
            return
        elif action == "static" and len(_cmdlist) >= 2:
            if _cmdlist[1] in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics[_cmdlist[1]])
            else:
                self.send_error(404, "invalid static object")
            return
        
        self.send_error(400, "invalid action")
    
    def do_PUT(self):
        reqheader=reference_header.copy()
        pos_header = self.path.find("?")
        if pos_header != -1:
            _cmdlist = self.path[1:pos_header].split("/")
            tparam = self.path[pos_header+1:].split("&")
            for elem in tparam:
                elem = elem.split("=")

                if len(elem) == 1 and elem[0] != "":
                    reqheader[elem[0]] = ""
                elif len(elem) == 2:
                    reqheader[elem[0]] = elem[1]
                else:
                    self.send_error(400,"invalid key/value pair\n{}".format(elem))
                    return
        else:
            _cmdlist = self.path[1:].split("/")
        action = _cmdlist[0]
        _cmdlist = _cmdlist[1:]
        if action == "do":
            self.handle_client(_cmdlist)
            return
        elif action == "put":
            self.handle_client_post(_cmdlist) #removes do


    def do_POST(self):
        plugin, action=self.path[1:].split("/",1)
        pluginm = self.links["client_server"].pluginmanager
        if pluginm is None:
            return
        if pluginm.redirect_addr in ["",None]:
            if "receive" in pluginm.plugins[plugin].__dict__:
                try:
                    pluginm.plugins[plugin].receive(action, self.rfile, self.wfile)
                except Exception as e:
                    logger().error(e)
                    return
        else:
            sockd= self.links["client_client"].do_request(pluginm.redirect_addr, \
                                            self.path, requesttype = "POST")
            redout=threading.Thread(target=rw_socket,args=(self.socket,sockd))
            redout.daemon=True
            redout.run()
            rw_socket(sockd,self.socket)
            return
        
        
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
        
        client_handler.salt = os.urandom(8)
        if confm.getb("remote") == True:
            client_handler.handle_remote = True
        if confm.getb("cpwhash") == True:
            client_handler.cpwhash=confm.get("cpwhash")
        elif confm.getb("cpwfile") == True:
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
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)

        if confm.getb("port") == True:
            port = int(port)
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = 0

        self.links["client_server"] = client_server(_name[0], confm.get("priority"), dhash(pub_cert), _message)
        self.links["client_server"].pluginmanager=pluginm
        self.links["configmanager"] = confm

        client_handler.links=self.links
        self.links["server"]=http_client_server(("",port),_cpath+"_cert")
        self.links["client"]=client_client(_name[0],dhash(pub_cert),os.path.join(self.links["config_root"], "certdb.sqlite"),self.links)
        
        
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
            eperm="{}(admin)".format(elem)
        else:
            eperm=elem
        if elem in cmdanot:
            out+="{}{}: {}".format(eperm,*cmdanot[elem])+"\n"
        else:
            out+="{}: {}".format(eperm,"<undocumented>")+"\n"

    out+="""
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
(s/c)pwhash=<hash>: sha256 hash of pw, higher preference than pwfile
(s/c)pwfile=<file>: file with password (cleartext)
remote: remote reachable
priority=<number>: set priority
timeout=<number>: #########not implemented yet ###############
webgui: enables webgui
cmd: opens cmd
s: set password for contacting client
c: set password for using client webcontrol
"""
    
def signal_handler(_signal, frame):
  sys.exit(0)


#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args={"noplugins":None,
             "cpwhash":None,
             "cpwfile":None,
             "apwhash":None,
             "apwfile":None,
             "spwhash":None,
             "spwfile":None,
             "remote":None,
             "priority":"20",
             "timeout":"300", # not implemented yet
             "webgui":None,
             "cmd":None}
             
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
    confm = configmanager(os.path.join(configpath, "config", "clientmain.conf"))
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
        pluginm.resources["access"] = cm.links["client"].access
        pluginm.init_plugins()

    if confm.getb("cmd")!=False:
        logger().debug("start client server")
        cm.serve_forever_nonblock()
        logger().debug("start console")
        print(*cm.links["client"].show({})[1],sep="/")
        while True:
            ret=cm.links["client"].command(input("Enter command, seperate by \"/\"\nEnter headers by closing command with \"?\" and\nadding key1=value1&key2=value2 key/value pairs:\n"))
            if ret[0] == True:
                if ret[2] == isself:
                    print("This client:")
                else:
                    print("{} with hash:\n{}\n answers:".format(ret["certname"],ret["hash"]))
            print(ret[1])
        #cm.cmd_cmd()
    else:
        logger().debug("start client server")
        cm.serve_forever_block()
