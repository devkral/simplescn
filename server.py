#! /usr/bin/env python3

from http.server  import BaseHTTPRequestHandler,HTTPServer
import ssl
#import socket
import logging
import sys,signal,threading


from common import success,error,server_port,client_port,check_certs,generate_certs,init_config_folder,default_configdir,workaround_ssl

from os import path

class server(object):
    pub_cert=None
    nhipmap=None
    nhlist_cache=None
    
    def __init__(self,_pub_cert):
        self.nhipmap={}
        self.nhlist_cache=""
        self.pub_cert=_pub_cert.decode("utf8")

    def register(self,_name,_hash,_port,_addr=None):
        if _addr is None: # if port is none
            _addr=_port
            _port=client_port
        self.nhipmap[_name]={_hash: (_addr[0],_port)}
        self.nhlist_cache="{}/{}\n{}".format(_name,_hash,self.nhlist_cache)
        return success
    
    def connect(self,_name,_hash,_addr):
        return error
    def get(self,_name,_hash,_addr):
        if _name not in self.nhipmap:
            return "{}name".format(error)
        if _hash not in self.nhipmap[_name]:
            return "{}certhash".format(error)
        return "{}{}/{}".format(success,*self.nhipmap[_name][_hash])
    def cert(self,_addr):
        return success+self.pub_cert
    def listnames(self,_addr):
        return success+self.nhlist_cache

    
class server_handler(BaseHTTPRequestHandler):
    linkback=None
    validactions=["register","connect","get","cert","listnames"]
       
        
    def index(self):
        self.send_response(200)
        self.send_header('Content-type',"text/html")
        self.end_headers()
        self.wfile.write("TODO")
            
    def do_GET(self):
        _path=self.path[1:].split("/")
        if _path[0]=="":
            self.index()
            return
        action=_path[0]
        if action=="index":
            self.index()
            return
        _path=_path+[self.client_address,]
        if action not in self.validactions:
            self.send_error(400,"invalid actions")
            return
        try:
            func=type(self.linkback).__dict__[action]
            response=func(self.linkback,*_path[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                self.send_error(500,str(e))
            return
        respparse=response.split("/",1)
        if respparse[0]=="error":
            self.send_error(400,respparse[1])
        else:
            self.send_response(200)
            self.send_header('Content-type',"text")
            self.end_headers()
            self.wfile.write(bytes(respparse[1],"utf8"))
        
        
def inputw():
    input("Please enter passphrase:\n")
    
class http_server_server(HTTPServer):
    socket=None
    server_server=None
    crappyssl=None

    def __del__(self):
        self.crappyssl.close()
  
    def __init__(self, server_address,certs):
        e=server_handler
        self.server_server=server(certs[1])
        e.linkback=self.server_server
        self.crappyssl=workaround_ssl(certs[1])

        
        HTTPServer.__init__(self, server_address,e)
        """tcontext=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        tcontext.set_ciphers("HIGH")
        tcontext.options=tcontext.options|ssl.OP_SINGLE_DH_USE|ssl.OP_SINGLE_ECDH_USE|ssl.OP_NO_COMPRESSION
        tcontext.load_cert_chain(self.crappyssl.name,certs[0])
        self.socket=tcontext.wrap_socket(tcontext)"""


    """def shutdown_request(self, request):
        if request is None:
            return
        try:
            # explicitly shutdown.  socket.close() merely releases
            # the socket and waits for GC to perform the actual close.
            request.shutdown() # shutdown of sslsocketwrapper
            request.sock_shutdown(socket.SHUT_RDWR) # hard shutdown of underlying socket
        except (OSError):
            pass # some platforms may raise ENOTCONN here
        except Exception as e:
            logging.error("Exception while shutdown")
            logging.error(e)
            self.close_request(request)

    def close_request(self,request):
        if request is None:
            return
        try:
            request.close()
        except Exception as e:
            logging.error(e)"""
#
class server_init(object):
    config_path=None
    server=None
    
    def __init__(self,_configpath,_port=None):
        self.config_path=path.expanduser(_configpath)
        init_config_folder(self.config_path)
        if check_certs(self.config_path+"server_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(self.config_path+"server_cert")
            logging.debug("Certificate generation complete")
        """with open(self.config_path+"server_cert"+".priv", 'rb') as readinprivkey:
            priv_cert=readinprivkey.read()"""
        with open(self.config_path+"server_cert"+".pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()
        with open(self.config_path+"server", 'r') as readserver:
            try:
                _server=readserver.readline().split("/")
            except Exception as e:
                print("Configuration error in {}".format(self.config_path+"server"))
                print("<name>/<port>")
                raise(e)
        if None in [pub_cert,_server]:
            raise(Exception("missing"))
        

        if _port is not None:
            _port=int(_port)
        elif len(_server)>=2:
            _port=int(_server[1])
        else:
            _port=server_port
        self.server=http_server_server(("0.0.0.0",_port),(self.config_path+"server_cert"+".priv",pub_cert))

    def serve_forever_block(self):
        self.server.serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()



def signal_handler(_signal, frame):
    sys.exit(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    cm=server_init(default_configdir)
    logging.debug("server started. Enter mainloop")
    cm.serve_forever_block()
