#! /usr/bin/env python3

import sys,os

sharedir=None
if sharedir is None:
    sharedir=os.path.dirname(os.path.realpath(__file__))

if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)


from http.server  import BaseHTTPRequestHandler,HTTPServer
import time
#import socket
import signal,threading
import socketserver #,socket
import traceback
import socket
import logging


from common import success, error, server_port, check_certs,generate_certs,init_config_folder, default_configdir, default_sslcont, check_name, dhash_salt, gen_passwd_hash, rw_socket, dhash, commonscn, pluginmanager, configmanager, logger





class server(commonscn):
    capabilities=["basic",]
    nhipmap=None
    nhipmap_cache=""
    nhipmap_len=0
    sleep_time=1
    refreshthread=None
    isactive=True
    links=None
    expire_time=100
    scn_type="server"

    validactions={"register","get","listnames","info","cap","prioty","num_nodes"}
    
    def __init__(self,d):
        self.expire_time=int(d["expire"])*60 #in minutes        
        self.nhipmap={}
        self.nhipmap_cond=threading.Event()
        self.changeip_sem=threading.Semaphore(1)
        self.refreshthread=threading.Thread(target=self.refresh_nhipmap)
        self.refreshthread.daemon=True
        self.refreshthread.start()
        
        if d["name"] is None or len(d["name"])==0:
            logger().debug("Name empty")
            d["name"]="<noname>"
        
        #self.msg=_msg
        if d["message"] is None or len(d["message"])==0:
            logger().debug("Message empty")
            d["message"]="<empty>"
        
        self.priority=int(d["priority"])
        self.cert_hash=d["certhash"]
        self.name=d["name"]
        self.message=d["message"]
        self.update_cache()

    def __del__(self):
        self.isactive=False
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as e:
            logger().error(e)
            
            
    def refresh_nhipmap(self):
        while self.isactive:
            self.changeip_sem.acquire()
            self.nhipmap_len=len(self.nhipmap)
            e_time=int(time.time())-self.expire_time
            tnhlist=""
            for _name in self.nhipmap:
                for _hash in self.nhipmap[_name]:
                    if self.nhipmap[_name][_hash][2]<e_time:
                        del self.nhipmap[_name][_hash]
                    else:
                        tnhlist="{}\n{}/{}".format(tnhlist,_name,_hash)
            self.nhipmap_cache=tnhlist[1:]
            self.changeip_sem.release()
            self.nhipmap_cond.clear()
            time.sleep(self.sleep_time)
            self.nhipmap_cond.wait()
  

    def register(self,_name,_hash,_port,_addr):
        if check_name(_name)==False:
            return "{}/invalid name".format(error)
        self.changeip_sem.acquire(False)
        self.nhipmap[_name]={_hash: (_addr[0],_port,int(time.time()))}
        self.changeip_sem.release()
        self.nhipmap_cond.set()
        return "{}/registered".format(success)
    
    
    def get(self,_name,_hash,_addr):
        if _name not in self.nhipmap:
            return "{}/name not exist".format(error)
        if _hash not in self.nhipmap[_name]:
            return "{}/certhash not exist".format(error)
        return "{}/{}:{}".format(success,*self.nhipmap[_name][_hash][:2])
    
    def listnames(self,_addr):
        if len(self.nhipmap_cache)==0:
            return "{}/empty".format(success)
        return "{}/{}".format(success,self.nhipmap_cache)
    
    def info(self,_addr):
        return self.cache["info"]
    
    def cap(self,_addr):
        return self.cache["cap"]
    
    def prioty(self,_addr):
        return self.cache["prioty"]

    def num_nodes(self,_addr):
        return "{}/{}".format(success,self.nhipmap_len)
    
    
class server_handler(BaseHTTPRequestHandler):

    server_version = 'simple scn server 0.5'
    
    
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
    
    statics={}
        
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
    """
    WWW-Authenticate: Digest realm="testrealm@host.com",
                        qop="auth,auth-int",
                        algorithm="SHA256", or should I use SHA256session
                        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                        opaque="5ccc069c403ebaf9f0171e9517f40e41"
                        """
    #check server password
    def check_spw(self):
        if self.spwhash is None:
            return True
        if "spwhash" in self.headers:
            if dhash_salt(self.headers["spwhash"],self.salt)==self.spwhash:
                return True
        return False
    """
    WWW-Authenticate: Digest realm="testrealm@host.com",
                        qop="auth,auth-int",
                        algorithm="SHA256", or should I use SHA256session
                        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                        opaque="5ccc069c403ebaf9f0171e9517f40e41"
                        """
    #check server password
    def check_tpw(self):
        if self.tpwhash is None:
            return True
        if "tpwhash" in self.headers:
            if dhash_salt(self.headers["tpwhash"],self.salt)==self.tpwhash:
                return True
        return False

    
    def do_GET(self):
        if self.path=="/favicon.ico":
            #print(server_handler.statics)
            if "favicon.ico" in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics["favicon.ico"])
            else:
                self.send_error(404)
            return
        
        if self.check_spw()==False:
            self.send_error(401,self.salt)
            return
        
        _path=self.path[1:].split("/")
        action=_path[0]
        if action in ("","server","html","index"):
            self.html("server.html")
            return
        elif self.webgui==True and action=="static" and len(_path)>=2:
            if _path[1] in self.statics:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.statics[_path[1]])
            else:
                self.send_error(404)
            return
        
        _path=_path+[self.client_address,]
        if action not in self.links["server_server"].validactions:
            self.send_error(400,"invalid action")
            return
        try:
            func=type(self.links["server_server"]).__dict__[action]
            response=func(self.links["server_server"],*_path[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                if "tb_frame" in e.__dict__:
                    st=str(e)+"\n\n"+str(traceback.format_tb(e))
                else:
                    st=str(e)
                #helps against ssl failing about empty string (EOF)
                if len(st)>0:
                    self.send_error(500,st)
                else:
                    self.send_error(500,"unknown")
            return
        respparse=response.split("/",1)
        if respparse[0]==error:
            #helps against ssl failing about empty string (EOF)
            if len(respparse)>=1 and len(respparse[1])>0:
                self.send_error(400,respparse[1])
            else:
                self.send_error(400,"unknown")
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "no-cache")
            self.send_header('Content-type',"text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(respparse)>=1 and len(respparse[1])>0:
                self.wfile.write(bytes(respparse[1],"utf8"))
            else:
                self.wfile.write(bytes(success,"utf8"))

    def do_CONNECT(self):
        if self.istunnel==False:
            self.send_error(400,"no tunnel/proxy")
            return
        if self.check_tpw()==False:
            self.send_error(407,self.salt)
            return
        port_i=self.path.find(":")
        if port_i>=0:
            if self.path[port_i+1:].isdecimal()==True:
                dest=(self.path[:port_i],int(self.path[port_i+1:]))
            else:
                self.send_error(400,"portnumber invalid")
                return
        
        else:
            dest=(self.path[:port_i],80)
        try:
            sockd=socket.create_connection(dest,self.ttimeout)
                
        except Exception:
            self.send_error(400,"Connection failed")
            return
        
        self.send_response(200)
        #self.send_header('Connection established')
        #self.send_header(self.version_string())
        self.end_headers()
        redout=threading.Thread(target=rw_socket,args=(self.socket,sockd))
        redout.daemon=True
        redin=threading.Thread(target=rw_socket,args=(sockd,self.socket))
        redin.daemon=True
        redin.run()
        redout.run()
        redin.join()
    def do_POST(self):
        plugin,action=self.path[1:].split("/",1)
        pluginm=self.links["client_server"].pluginmanager
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
            self.links["server_server"].do_request(pluginm.redirect_addr, \
                                            self.path, requesttype = "POST")
            return
        
def inputw():
    input("Please enter passphrase:\n")
    
class http_server_server(socketserver.ThreadingMixIn,HTTPServer):
    sslcont=None
    #address_family = socket.AF_INET6
    
    #def __del__(self):
    #    self.crappyssl.close()
  
    def __init__(self, server_address,certfpath):
        socketserver.TCPServer.__init__(self, server_address, server_handler)
        #self.crappyssl=workaround_ssl(certs[1])

        self.sslcont=default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv")
        self.socket=self.sslcont.wrap_socket(self.socket)


class server_init(object):
    config_path=None
    links=None
    sthread=None
    
    def __init__(self,_configpath, **kwargs):
        self.config_path=_configpath
        _spath=os.path.join(self.config_path,"server")
        port=kwargs["port"]
        init_config_folder(self.config_path,"server")
        
        server_handler.salt = os.urandom(8)
        if kwargs["spwhash"] is not None:
            server_handler.spwhash = dhash_salt(kwargs["spwhash"],server_handler.salt)
        elif kwargs["spwfile"] is not None:
            op=open("r")
            server_handler.spwhash = gen_passwd_hash(op.readline())
            op.close()
        if kwargs["tunnel"] is not None:
            server_handler.istunnel = True
        if kwargs["tpwhash"] is not None:
            server_handler.tpwhash = dhash_salt(kwargs["tpwhash"],server_handler.salt)
        elif kwargs["tpwfile"] is not None:
            op=open("r")
            server_handler.tpwhash=gen_passwd_hash(op.readline())
            op.close()
        server_handler.ttimeout=int(kwargs["ttimeout"])
        server_handler.stimeout=int(kwargs["stimeout"])

        
        self.links={}
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
            print("Configuration error in {}".format(_spath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            

        
        if port is not None:
            port=int(port)
        elif len(_name)>=2:
            _port=int(_name[1])
        else:
            _port=server_port
        serverd={"name":_name[0],"certhash":dhash(pub_cert),
                "priority":kwargs["priority"],"message":_message,
                "expire":kwargs["expire"]}
        
        self.links["server_server"]=server(serverd) 
        #self.links["server_server"].configmanager=configmanager(self.config_path+os.sep+"main.config")
            #self.links["server_server"].pluginmanager.interfaces+=["server"]
            
        server_handler.links=self.links
        
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
ttimeout: tunneltimeout
stimeout: server timeout
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
             "ttimeout":"300",
             "stimeout":"30"}
    
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
    
        pluginm=pluginmanager(pluginpathes, plugins_config)
        if server_args["webgui"] is not None:
            pluginm.interfaces+=["web",]
        cm.links["server_server"].pluginmanager=pluginm
        pluginm.init_plugins()
        
    logger().debug("server started. Enter mainloop")
    cm.serve_forever_block()
