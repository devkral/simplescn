#! /usr/bin/env python3
import logging
import signal
import sys
import os
import threading
from os import path
from gi.repository import Gtk,Gdk,Gio


import client
from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,dhash


class gtk_client_server(client.client_server):
    pass


class gtk_client_init(client.client_init):

    def __init__(self,**kwargs):
        self.config_path=path.expanduser(kwargs["config"])
        if self.config_path[-1]==os.sep:
            self.config_path=self.config_path[:-1]
        _cpath="{}{}{}".format(self.config_path,os.sep,"client")
        init_config_folder(self.config_path,"client")
        
        client.client_handler.salt=os.urandom(4)
        port=kwargs["port"]
        if check_certs(_cpath+"_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logging.debug("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert=readinpubkey.read()

        with open(_cpath+"_name", 'r') as readclient:
            _name=readclient.readline()
        with open(_cpath+"_message", 'r') as readinmes:
            _message=readinmes.read()
            if _message[-1] in "\n":
                _message=_message[:-1]
        #report missing file
        if None in [pub_cert,_name,_message]:
            raise(Exception("missing"))
        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)

        

                
        if port is not None:
            port=int(port)
        elif len(_name)>=2:
            port=int(_name[1])
        else:
            port=0
            
        self.links["client_server"]=gtk_client_server(_name[0],kwargs["priority"],_message)
        client.client_handler.links=self.links
        self.links["server"]=client.http_client_server(("0.0.0.0",port),_cpath+"_cert")
        self.links["client"]=client.client_client(_name[0],dhash(pub_cert),self.config_path+os.sep+"certdb.sqlite",self.links)

    def serve_forever_block(self):
        self.links["server"].serve_forever()
    def serve_forever_nonblock(self):
        self.sthread = threading.Thread(target=self.serve_forever_block)
        self.sthread.daemon = True
        self.sthread.start()



def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
port=<number>: Port
priority=<number>: set priority
timeout=<number>: #########not implemented yet ###############
cmd: opens cmd
s: set password for contacting client
c: set password for using client webcontrol
""")

run=True
def signal_handler(*args):
    global run
    #win.close()
    run=False
    #app.close()

  
if __name__ ==  "__main__":
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    d={"config":default_configdir,
       "port":None,
       "priority":"20",
       "timeout":"300", # not implemented yet
       "cmd":None}
    
    if len(sys.argv)>1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem=elem.strip("-")
            if elem in ["help","h"]:
                paramhelp()
                sys.exit(0)
            else:
                tparam=elem.split("=")
                if len(tparam)==1:
                    tparam=elem.split(":")
                if len(tparam)==1:
                    d[tparam[0]]=""
                    continue
                d[tparam[0]]=tparam[1]
                

    client.client_handler.webgui=False

                
    cm=gtk_client_init(**d)
    logging.debug("start server")
    cm.serve_forever_noblock()
    while run==True:
        Gtk.main_iteration_do(True)
  
    sys.exit(0)