#! /usr/bin/env python3
import logging
import signal
import sys
import os
import threading
from os import path
from gi.repository import Gtk,Gdk,Gio


import client
from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,dhash,sharedir,VALError,isself


class gtk_client(object):
    builder=None
    clip=None
    win=None
    statusbar=None
    nodeview=None
    nodestore=None
    param_client={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None}
    param_server={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None}

    cert_hash=None

    def __init__(self,client="[::1]:<port>",clientpw=None,certhash=None):
        self.cert_hash=certhash
        self.__dict__["do_request"]=client.client_client.__dict__["do_request"]
        self.builder=Gtk.Builder.new_from_file(sharedir+"gui/gtksimplescn.ui")
        self.builder.connect_signals(self)
        
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.win=self.builder.get_object("mainwindow")
        self.nodeview=self.builder.get_object("nodeview")
        self.nodestore=self.builder.get_object("nodestore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        
        col0renderer=Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("Name", col0renderer, text=0)
        col1renderer=Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("Hashes", col1renderer, text=1)
        col2renderer=Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Type", col2renderer, text=2)
        col3renderer=Gtk.CellRendererText()
        col3 = Gtk.TreeViewColumn("Verified", col3renderer, text=3)
        self.nodeview.append_column(col0)
        self.nodeview.append_column(col1)
        self.nodeview.append_column(col2)
        self.nodeview.append_column(col3)
        self.nodeview.get_selection().select_path(Gtk.TreePath.new_first())
        #"localhost:<port>"

    #replaced by client
    def do_request(self,_addr,requeststr,dparam,usecache=False,forceport=False):
        pass
    def init2(self):
        self.gtkupdate_clientinfo()
        self.gtkupdate_nodes()

    
    def internchat(self,_partner,_message=None):
        pass

    # 
    def chat(self,_message):
        pass

    def gtkupdate_clientinfo(self,*args):
        _info=self.builder.get_object("clientinfo")
        _info.set_text("Clientinfo: {}/{}/{}".format(*self.show()[1]))
    
    def gtkregister(self,*args):
        _veristate=self.builder.get_object("veristate")
        _server=self.builder.get_object("server").get_text().strip(" ").rstrip(" ")
        if _server=="":
            return
        try:
            temp=self.register(_server,self.param_server)
        except VALError as e:
            logging.info(e)
            _veristate.set_text("invalid")
            return
        if temp[0]==True and temp[2] is not None:
            if temp is isself:
                _veristate.set_text("Server is own client") # normally impossible
            else:
                _veristate.set_text("Server verified as:\n"+temp[2])
        else:
            _veristate.set_text("unverified")
        if temp[0]==True:
            logging.info("registered")
        else:
            logging.info("registration failed")
        
        
        
    def gtkgo(self,*args):
        _veristate=self.builder.get_object("veristate")
        _server=self.builder.get_object("server").get_text().strip(" ").rstrip(" ")
        _name=self.builder.get_object("name").get_text().strip(" ").rstrip(" ")
        _hash=self.builder.get_object("hash").get_text().strip(" ").rstrip(" ")
        _client=self.builder.get_object("client")

        if "" in [_server, _name, _hash]:
            return
        
        try:
            temp=self.get(_server,_name,_hash,self.param_server)
        except VALError as e:
            logging.info(e)
            _veristate.set_text("invalid")
            return
        except Exception as e:
            logging.error(e)
            return
        if temp[0]==True and temp[2] is not None:
            if temp is isself:
                _veristate.set_text("Server is own client") # normally impossible
            else:
                _veristate.set_text("Server verified as:\n"+temp[2])
        else:
            _veristate.set_text("unverified")
        if temp[0]==True:
            _client.set_text("{}:{}".format(*temp[1]))
            self.param_client["certhash"]=_hash

    def gtkinvalidate(self,*args):
        self.param_client["certname"]=None
        self.param_client["certhash"]=None
    def gtkchat(self,*args):
        pass

    def gtkupdate_nodes(self,*args):
        _nodestore=self.builder.get_object("nodestore")
        _localnames=self.listnamesl(self.param_client)
        if _localnames[0]==False:
            return
        _nodestore.clear()
        for elem in _localnames[1]:
#            print(elem)
            if elem[2]==None:
                _nodestore.append((elem[0],"","",""))
            else:
                _nodestore.append(("",str(elem[1]),elem[2],"local"))

        pass
    def gtkadd_node(self,*args):
        pass
    def gtkdel_node(self,*args):
        pass
    def gtkmod_node(self,*args):
        pass

    def gtkshow_services(self,*args):
        smw=self.builder.get_object("servicemw")
        if smw.get_visible()==False:
            smw.show_all()
        else:
            smw.hide()
    def gtkhide_services(self,*args):
        smw=self.builder.get_object("servicemw")
        smw.hide()
        
    def gtkupdate_services(self,*args):
        pass

    def gtkadd_service(self,*args):
        pass
    def gtkdel_service(self,*args):
        pass
    def gtkmod_service(self,*args):
        pass


    def gtkclose(self,*args):
        global run
        run=False


class gtk_client_init(client.client_init):

    def __init__(self,**kwargs):
        self.config_path=path.expanduser(kwargs["config"])
        if self.config_path[-1]==os.sep:
            self.config_path=self.config_path[:-1]
        _cpath="{}{}{}".format(self.config_path,os.sep,"client")
        init_config_folder(self.config_path,"client")
        
        if check_certs(_cpath+"_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logging.debug("Certificate generation complete")

        with open(_cpath+"_name", 'r') as readclient:
            _name=readclient.readline()
        #report missing file
        if None in [_name,]:
            raise(Exception("missing"))
        
        _name=_name.split("/")
        if len(_name)>2 or check_name(_name[0])==False:
            print("Configuration error in {}".format(_cpath+"_name"))
            print("should be: <name>/<port>")
            print("Name has some restricted characters")
            sys.exit(1)

        if kwargs["client"] is not None:
            _client=kwargs["client"]
            if len(kwargs["client"].rsplit(":",1))==1:
                if len(_name)>=2:
                   _client=kwargs["client"]+":"+_name[1]
        else:
            _client="localhost:<port>"

        
        if kwargs["server"] is not None:
            client.client_init(self,**kwargs)
            _client="localhost:".format(self.links["server"].socket.getsockname()[1])
            gtk_client(client=_client,clientpw=kwargs["clientpw"],certhash=kwargs["certhash"])
        else:
            gtk_client(client=_client,clientpw=kwargs["clientpw"],certhash=kwargs["certhash"])


def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
priority=<number>: set priority (disfunct here set directly)
timeout=<number>: #########not implemented yet ###############
server: shall start own server
port=<number>: Port in connection with server
client: url to connect
clientpw: pw for the url
cmd: opens cmd
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
       "server":None,
       "client":None,
       "clientpw":None,
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
    if d["server"] is not None:
        logging.debug("start server")
        cm.serve_forever_nonblock()
    while run==True:
        Gtk.main_iteration_do(True)
  
    sys.exit(0)
