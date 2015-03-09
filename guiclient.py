#! /usr/bin/env python3
import logging
import signal
import sys
import os
import traceback#threading,
from os import path
from gi.repository import Gtk,Gdk,Gio


import client
from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,sharedir,VALError,isself,default_sslcont


class gtk_client(object):
    builder=None
    clip=None
    win=None
    statusbar=None
    nameview=None
    namestore=None
    param_client={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_server={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}

    cert_hash=None
    #start_url_hash=(None,None)

    def __init__(self,client=None,clientpw=None,certhash=None):
        self.sslcont=default_sslcont()
        self.cert_hash=certhash
        #self.clienturl=client # other lock method
        self.cert_hash_backup=certhash
        self.builder=Gtk.Builder.new_from_file(sharedir+"gui/gtksimplescn.ui")
        self.builder.connect_signals(self)
        
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.win=self.builder.get_object("mainwindow")
        self.nameview=self.builder.get_object("nameview")
        self.namestore=self.builder.get_object("namestore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        
        col0renderer=Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("CertName", col0renderer, text=0)
        self.nameview.append_column(col0)
        self.nameview.get_selection().select_path(Gtk.TreePath.new_first())
        if client is not None:
            self.builder.get_object("clienturl").set_text(client)
            if len(client.rsplit(":",1))>1:
                self.builder.get_object("lockclientcheck").set_active(True)
            self.gtktogglelock()
        if clientpw is not None:
            self.builder.get_object("clientpw").set_text(clientpw)
        self.gtkupdate_clientinfo()

    def do_request(self,requeststr):
        clienturl=self.builder.get_object("clienturl").get_text().strip().rstrip()
        try:
            return client.client_client.__dict__["do_request"](self,clienturl,requeststr,self.param_client,usecache=False,forceport=False)
        except Exception as e:
            if "tb_frame" in e.__dict__:
                st=str(e)+"\n\n"+str(traceback.format_tb(e))
            else:
                st=str(e)

            logging.error(st)
            return (False, e,"isself")
    
    def do_requestdo(self,*requeststrs):
        temp="/do"
        for elem in requeststrs:
            temp="{}/{}".format(temp,elem)
        return self.do_request(temp)
        
    
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
        gtklock=self.builder.get_object("lockclientcheck")
        temp=self.do_requestdo("show")
        if temp[0]==True:
            if len(temp[1].split("\n"))>2:
                _info.set_text("Clientinfo: {}/{}/{}".format(*temp[1].split("\n",2)))
            else:
                gtklock.set_active(False)
                self.gtktogglelock()
                logging.error(temp[1])
        else:
            gtklock.set_active(False)
            self.gtktogglelock()
            logging.error(temp[1])
                           
    
    def gtkregister(self,*args):
        _veristate=self.builder.get_object("veristate")
        _server=self.builder.get_object("serverurl").get_text().strip(" ").rstrip(" ")
        if _server=="":
            return

        try:
            temp=self.do_requestdo("register",_server)
        except VALError as e:
            logging.info(e)
            _veristate.set_text("invalid")
            return
        if temp[0]==True and temp[2] is not None:
            if temp == "isself":
                _veristate.set_text("Server is own client") # normally impossible
            else:
                _veristate.set_text("Server verified as:\n"+temp[2])
        else:
            _veristate.set_text("unverified")
        if temp[0]==True:
            logging.info("registered")
        else:
            print(temp[1])
            logging.info("registration failed")
        
    def gtkupdate_clienturl(self,*args):
        _client=self.builder.get_object("clienturl").get_text().strip(" ").rstrip(" ")
        if _client=="":
            return
        
    def gtktogglelock(self,*args):
        gtklock=self.builder.get_object("lockclientcheck")
        if gtklock.get_active()==True:
            self.builder.get_object("clienturl").set_sensitive(False)
            self.builder.get_object("clientpw").set_sensitive(False)
            self.builder.get_object("clientinfoexpander").set_expanded(False)
        else:
            self.builder.get_object("clienturl").set_sensitive(True)
            self.builder.get_object("clientpw").set_sensitive(True)
            self.builder.get_object("clientinfoexpander").set_expanded(True)
        
    def gtkgo(self,*args):
        _veristate=self.builder.get_object("veristate")
        _server=self.builder.get_object("serverurl").get_text().strip(" ").rstrip(" ")
        _name=self.builder.get_object("name").get_text().strip(" ").rstrip(" ")
        _hash=self.builder.get_object("hash").get_text().strip(" ").rstrip(" ")
        _node=self.builder.get_object("nodeurl")

        if "" in [_server, _name, _hash]:
            return
        
        try:
            temp=self.do_requestdo("get",_server,_name,_hash)
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
            _node.set_text("{}:{}".format(*temp[1].split("\n")))
            self.param_client["certhash"]=_hash

    def gtkchat(self,*args):
        pass

            
    def gtkinvalidate(self,*args):
        self.param_client["certname"]=None
        self.param_client["certhash"]=None

    def gtkupdate_names(self,*args):
        _localnames=self.do_requestdo("listnamecerts")
        if _localnames[0]==False:
            return
        self.namestore.clear()
        for elem in _localnames[1].split("/"):
            self.namestore.append((elem,))

    def gtkadd_name(self,*args):
        _tgan=self.builder.get_object("nameaddentry")
        _tgan.set_text("")
        _tgan.show()
    
    def gtkadd_nameconfirm(self,*args):
        _tgan=self.builder.get_object("nameaddentry")
        _tname=_tgan.get_text()
        if _tname=="":
            _tgan.hide()
            _tgan.set_text("")
            return
        _tcname=self.do_requestdo("addname",_tname)
        if _tcname[0]==True:
            _tgan.hide()
            _tgan.set_text("")
            
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
            if _name[-1]=="\n":
                _name=_name[:-1]
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
                   _client="{}:{}".format(kwargs["client"],_name[1])
        else:
            _client=None
            if len(_name)>=2:
                _client="localhost:{}".format(_name[1])

        if kwargs["server"] is not None:
            client.client_init(self,**kwargs)
            _client="localhost:".format(self.links["server"].socket.getsockname()[1])
            self.links["gtkclient"]=gtk_client(client=_client,clientpw=kwargs["clientpw"],certhash=kwargs["certhash"])
        else:
            self.links["gtkclient"]=gtk_client(client=_client,clientpw=kwargs["clientpw"],certhash=kwargs["certhash"])


def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
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
    d=client.client_args.copy()
    d.update({"config":default_configdir,
              "port":None,
              #set local to true (because elsewise program doesn't work with "server" set
              # "true" could also be ""
              "local": "true",
              "priority":"20",
              "timeout":"300", # not implemented yet
              "server":None,
              "client":None,
              "clientpw":None,
              "certhash":None,
              "cmd":None})
    
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

    
    #logging.debug("start client")
    cm=gtk_client_init(**d)
    logging.debug("client started")
    if d["server"] is not None:
        logging.debug("start server")
        cm.serve_forever_nonblock()
        
    logging.debug("enter mainloop")
    while run==True:
        Gtk.main_iteration_do(True)
  
    sys.exit(0)
