#! /usr/bin/env python3
import logging
import signal
import sys
import os
import traceback#threading,
from os import path
from gi.repository import Gtk,Gdk,Gio


import client
from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,sharedir,VALError,isself,default_sslcont,dhash,AddressFail


class gtk_client(object):
    builder=None
    clip=None
    win=None
    statusbar=None
    nameview=None
    namestore=None
    param_client={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_server={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_node={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}

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
        col0 = Gtk.TreeViewColumn("Name", col0renderer, text=0)
        self.nameview.append_column(col0)
        self.nameview.get_selection().select_path(Gtk.TreePath.new_first())
        if client is not None:
            self.builder.get_object("clienturl").set_text(client)
            if len(client.rsplit(":",1))>1:
                self.builder.get_object("lockclientcheck").set_active(True)
            self.gtktogglelock()
        if certhash is not None:
            self.builder.get_object("clienturl").set_sensitive(False)
            self.builder.get_object("clientpw").set_sensitive(False)
            self.builder.get_object("lockclientcheck").set_sensitive(False)
            self.builder.get_object("useclient").set_sensitive(False)
            self.builder.get_object("useclient").set_active(True)
            self.builder.get_object("clientinfoexpander").set_expanded(False)

        if clientpw is not None:
            self.builder.get_object("clientpw").set_text(clientpw)
            self.gtkupdate_clientpw()
        self.gtkupdate_clientinfo()
        self.gtkupdate_certnames()
        
    def do_request(self,requeststr):
        clienturl=self.builder.get_object("clienturl").get_text().strip().rstrip()
        params="?"
        for elem in ["certhash","certname"]:
            if self.param_node[elem] is not None:
                params="{}&{}".format(params,self.param_node[elem])

        if params[-1] in ["?","&"]:
            params=params[:-1]
        try:
            temp=client.client_client.__dict__["do_request"](self,clienturl,requeststr+params,self.param_client,usecache=False,forceport=False)
        except AddressFail:
            
            return (False, "",isself)
        except Exception as e:
            if "tb_frame" in e.__dict__:
                st=str(e)+"\n\n"+str(traceback.format_tb(e))
            else:
                st=str(e)

            logging.error(st)
            return (False, e,isself)
        if temp[0]==False:
            return temp
        temp1=temp[1].split("\n")
        _finish1=[]
        for elem in temp1:
            if elem=="%":
                _finish1+=[None,]
                continue
                
            _temp2=[]
            for elem2 in elem.split("&"):
                if elem2=="%":
                    _temp2+=[None,]
                else:
                    _temp2+=[elem2,]
            #remove array if just one element
            if len(_temp2)==1:
                _temp2=_temp2[0]
            #remove trailing "" element
            elif _temp2[0]=="":
                _temp2=_temp2[1:]
            _finish1+=[_temp2,]
        
        #remove array if just one element
        if len(_finish1)==1:
            _finish1=_finish1[0]
        #remove trailing "" element
        elif _finish1[0]=="":
            _finish1=_finish1[1:]
        
        return (temp[0],_finish1,temp[2])
        
    def do_requestdo(self,*requeststrs):
        temp="/do"
        for elem in requeststrs:
            temp="{}/{}".format(temp,elem)
        return self.do_request(temp)

    def do_requestdirect(self,*requeststrs):
        _treqstr=""
        for elem in requeststrs:
            _treqstr="{}/{}".format(_treqstr,elem)
        serverurl=self.builder.get_object("serverurl").get_text().strip().rstrip()
        try:
            return client.client_client.__dict__["do_request"](self,serverurl,_treqstr,self.param_node,usecache=False,forceport=False)
        except Exception as e:
            if "tb_frame" in e.__dict__:
                st=str(e)+"\n\n"+str(traceback.format_tb(e))
            else:
                st=str(e)

            logging.error(st)
            return (False, e,isself)

    def gethash_intern(self,_addr):
        try:
            return client.client_client.gethash(self,_addr,{})
        except Exception as e:
            return (False,e,isself)


    def updatehash_client(self,*args):
        #self.param_client["certhash"]=None
        clienturl=self.builder.get_object("clienturl").get_text()
        result=self.gethash_intern(clienturl)
        if result[0]==True:
            self.param_client["certhash"]=result[1][0]
    
    def updatehash_server(self,*args):
        #
        _veristate=self.builder.get_object("veristates")
        serverurl=self.builder.get_object("serverurl").get_text().strip(" ").rstrip(" ")
        if serverurl=="":
            return
        result=self.do_requestdo("ask",serverurl)
        if result[0]==True:
            if result[1][1] is None:
                self.param_server["name"]=None
                self.param_server["certhash"]=result[1][0]
            elif result[1][1] is isself:
                self.param_server["name"]=None
                self.param_server["certhash"]=result[1][0]
                _veristate.set_text("Server is own client") # normally impossible
            else:
                self.param_server["certhash"]=None
                self.param_server["name"]=result[1][1]
                _veristate.set_text("Server verified as:\n"+result[1][1])
        
    def internchat(self,_partner,_message=None):
        pass

    # 
    def chat(self,_message):
        pass

    def gtkupdate_clientinfo(self,*args):
        _info=self.builder.get_object("clientinfo")
        #gtklock=self.builder.get_object("lockclientcheck")
        temp=self.do_requestdo("show")
        if temp[0]==True:
            if not temp[2] is isself:
               logging.error("third arg is not isself\n{}".format(temp[2]))
               return
               
            if len(temp[1])>2:
                _info.set_text("Clientinfo: {}/{}/{}".format(*temp[1]))
                
            else:
                self.builder.get_object("clientinfoexpander").set_expanded(True)
                logging.error("len args does not match\n{}".format(temp[1]))
        else:
            self.builder.get_object("clientinfoexpander").set_expanded(True)
            logging.error("other error\n{}".format(temp[1]))
                           
    def gtkupdate_clientpw(self,*args):
        self.param_client["cpwhash"]=dhash(self.builder.get_object("clientpw").get_text())

    def gtkupdate_serverpw(self,*args):
        self.param_client["spwhash"]=dhash(self.builder.get_object("serverpw").get_text())
        self.param_server["spwhash"]=dhash(self.builder.get_object("serverpw").get_text())
        

        
    def gtkregister(self,*args):
        _veristate=self.builder.get_object("veristates")
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
        
    
        
    def gtktogglelock(self,*args):
        if self.cert_hash is not None:
            return
        gtklock=self.builder.get_object("lockclientcheck")
        if gtklock.get_active()==True:
            self.builder.get_object("clienturl").set_sensitive(False)
            self.builder.get_object("clientpw").set_sensitive(False)
            self.builder.get_object("clientinfoexpander").set_expanded(False)
        else:
            self.builder.get_object("clienturl").set_sensitive(True)
            self.builder.get_object("clientpw").set_sensitive(True)
            self.builder.get_object("clientinfoexpander").set_expanded(True)
        
    def gtkget(self,*args):
        _veristate=self.builder.get_object("veristates")
        _servero=self.builder.get_object("serverurl")
        _server=_servero.get_text().strip(" ").rstrip(" ")
        if _server=="":
            return
        _nameo=self.builder.get_object("name")
        _name=_nameo.get_text().strip(" ").rstrip(" ")
        if _name=="":
            return
        _hasho=self.builder.get_object("hash")
        _hash=_hasho.get_text().strip(" ").rstrip(" ")
        if _hash=="":
            return

        _nodeo=self.builder.get_object("nodeurl")

        try:
            if self.builder.get_object("useclient").get_active()==True:
                temp=self.do_requestdo("get",_server,_name,_hash)
            else:
                temp=self.do_requestdirect("get",_name,_hash)
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
            _nodeo.set_text("{}:{}".format(*temp[1]))
            self.param_node["certhash"]=_hash

    def gtkchat(self,*args):
        pass
        
    def gtknode_invalidate(self,*args):
        self.param_node["certname"]=None
        self.param_node["certhash"]=None

    def gtkupdate_certnames(self,*args):
        _localnames=self.do_requestdo("listcertnames")
        if _localnames[0]==False:
            return
        self.namestore.clear()
        for elem in _localnames[1]:
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
            if kwargs["cpwhash"] is None and \
               kwargs["cpwfile"] is None:
                pw=""
                for elem in os.urandom(20):
                    pw+=str(int(elem)%10)
                kwargs["cpwhash"]=dhash(pw)
                
            client.client_init.__init__(self,**kwargs)
            
            _client="localhost:{}".format(self.links["server"].socket.getsockname()[1])
            logging.debug("start server")
            self.serve_forever_nonblock()
            logging.debug("start gtkclient")
            self.links["gtkclient"]=gtk_client(client=_client,clientpw=pw,certhash=self.links["client"].cert_hash)
        else:
            logging.debug("start gtkclient")
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
    logging.debug("enter mainloop")
    while run==True:
        Gtk.main_iteration_do(True)
  
    sys.exit(0)
