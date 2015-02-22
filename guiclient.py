#! /usr/bin/env python3
import logging
import signal
import sys
import os
from gi.repository import Gtk,Gdk,Gio


import client
from common import default_configdir


def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
port=<number>: Port
(s/c)pwhash=<hash>: sha256 hash of pw, higher preference than pwfile
(s/c)pwfile=<file>: file with password (cleartext)
local: local reachable
remote: remote reachable
priority=<number>: set priority
timeout=<number>: #########not implemented yet ###############
webgui: enables webgui
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
       "cpwhash":None,
       "cpwfile":None,
       "spwhash":None,
       "spwfile":None,
       "local":None,
       "remote":None,
       "priority":"20",
       "timeout":"300", # not implemented yet
       "webgui":None,
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
                

    #should be gui agnostic so specify here
    if d["webgui"] is not None:
        logging.debug("webgui enabled")
        client.client_handler.webgui=True
        #load static files
        for elem in os.listdir("static"):
            with open("static{}{}".format(os.sep,elem), 'rb') as _staticr:
                client.client_handler.statics[elem]=_staticr.read()
    else:
        client.client_handler.webgui=False

                
    cm=client.client_init(**d)
        
    if d["cmd"] is not None:
        logging.debug("start server")
        cm.serve_forever_nonblock()
        logging.debug("start console")
        cm.cmd()
    else:
        logging.debug("start server")
        cm.serve_forever_noblock()
    while run==True:
        Gtk.main_iteration_do(True)
  
    sys.exit(0)
