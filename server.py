#! /usr/bin/env python3

from http.server  import BaseHTTPRequestHandler,HTTPServer
import time
#import socket
import logging
import sys,signal,threading
import socketserver #,socket


from common import success,error,server_port,check_certs,generate_certs,init_config_folder,default_configdir, default_sslcont

from os import path

class server(object):
    nhipmap=None
    nhlist_cache=""
    refreshthread=None
    isactive=True
    
    def __init__(self):
        self.nhipmap={}
        self.nhlist_cond=threading.Event()
        self.change_sem=threading.Semaphore(1)
        self.refreshthread=threading.Thread(target=self.refresh_nhlist)
        self.refreshthread.daemon=True
        self.refreshthread.start()

    def __del__(self):
        self.isactive=False
        self.nhlist_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as e:
            logging.error(e)

    def refresh_nhlist(self):
        while self.isactive:
            self.change_sem.acquire()
            tnhlist=""
            for _name in self.nhipmap:
                for _hash in self.nhipmap[_name]:
                    tnhlist="{}\n{}/{}".format(tnhlist,_name,_hash)
            self.nhlist_cache=tnhlist[1:]
            self.change_sem.release()
            self.nhlist_cond.clear()
            time.sleep(1)
            self.nhlist_cond.wait()
  

    def register(self,_name,_hash,_port,_addr):
        self.change_sem.acquire(False)
        self.nhipmap[_name]={_hash: (_addr[0],_port)}
        self.change_sem.release()
        self.nhlist_cond.set()
        return "{}registered".format(success)
    
    def connect(self,_name,_hash,_addr):
        return "{}unimplemented".format(error)
    
    def get(self,_name,_hash,_addr):
        if _name not in self.nhipmap:
            return "{}name".format(error)
        if _hash not in self.nhipmap[_name]:
            return "{}certhash".format(error)
        return "{}{}:{}".format(success,*self.nhipmap[_name][_hash])
    
    def listnames(self,_addr):
        if len(self.nhlist_cache)==0:
            return "{}empty".format(success)
        return "{}{}".format(success,self.nhlist_cache)

    
class server_handler(BaseHTTPRequestHandler):
    #linkback=None
    validactions=["register","connect","get","listnames"]
       
        
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
            func=type(self.server.server_server).__dict__[action]
            response=func(self.server.server_server,*_path[1:])
        except Exception as e:
            if self.client_address[0] in ["localhost","127.0.0.1","::1"]:
                #helps against ssl failing about empty string (EOF)
                l=str(e)
                if len(l)>0:
                    self.send_error(500,l)
                else:
                    self.send_error(500,"unknown")
            return
        respparse=response.split("/",1)
        if respparse[0]=="error":
            #helps against ssl failing about empty string (EOF)
            if len(respparse[1])>0:
                self.send_error(400,respparse[1])
            else:
                self.send_error(400,"unknown")
        else:
            self.send_response(200)
            self.send_header('Content-type',"text")
            self.end_headers()
            #helps against ssl failing about empty string (EOF)
            if len(respparse[1])>0:
                self.wfile.write(bytes(respparse[1],"utf8"))
            else:
                self.wfile.write(bytes("success","utf8"))
        
        
def inputw():
    input("Please enter passphrase:\n")
    
class http_server_server(socketserver.ThreadingMixIn,HTTPServer):
    server_server=None
    sslcont=None
    #def __del__(self):
    #    self.crappyssl.close()
  
    def __init__(self, server_address,certfpath):
        e=server_handler
        self.server_server=server()
        e.linkback=self.server_server
        socketserver.TCPServer.__init__(self, server_address, e)
        #self.crappyssl=workaround_ssl(certs[1])

        self.sslcont=default_sslcont()
        self.sslcont.load_cert_chain(certfpath+".pub",certfpath+".priv")
        self.socket=self.sslcont.wrap_socket(self.socket)


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
        with open(self.config_path+"server", 'r') as readserver:
            try:
                _server=readserver.readline().split("/")
            except Exception as e:
                print("Configuration error in {}".format(self.config_path+"server"))
                print("<name>/<port>")
                raise(e)
        if None in [_server]:
            raise(Exception("missing"))
        

        if _port is not None:
            _port=int(_port)
        elif len(_server)>=2:
            _port=int(_server[1])
        else:
            _port=server_port
        self.server=http_server_server(("0.0.0.0",_port),self.config_path+"server_cert")

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
