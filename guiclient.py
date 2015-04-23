#! /usr/bin/env python3
import logging
import signal
import sys
import os
import time,threading
import traceback#threading,
from os import path
from gi.repository import Gtk,Gdk
#,Gio


import client
from client import default_client_args as dclargs

from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,\
sharedir,isself,default_sslcont,dhash,AddressFail,\
scnparse_url,server_port,check_hash,configmanager,pluginmanager
#VALError

messageid=0

class gtkclient_node(logging.NullHandler):
    builder=None
    links=None

    def __init__(self,links,_address,shash=None):
        self.links=links
        
        self.builder=Gtk.Builder()
        self.builder.set_application(links["gtkclient"])
        self.builder.add_objects_from_file(sharedir+"gui/gtkclientnode.ui")
        
    
class gtkclient_server(logging.NullHandler):
    builder=None
    links=None

    def __init__(self,links,_address,shash=None):
        self.links=links
        
        self.builder=Gtk.Builder()
        self.builder.set_application(links["gtkclient"])
        self.builder.add_objects_from_file(sharedir+"gui/gtkclientserver.ui")

class gtkclient_info(logging.NullHandler):
    builder=None
    links=None

    def __init__(self,links,_address,shash=None):
        self.links=links
        
        self.builder=Gtk.Builder()
        self.builder.set_application(links["gtkclient"])
        self.builder.add_objects_from_file(sharedir+"gui/gtkclientmain.ui",["infowin",])
        

class gtkclient_main(logging.NullHandler,Gtk.Application):
    builder=None
    clip=None
    win=None
    backlog=[]
    statusbar=None
    localview=None
    localstore=None
    recentview=None
    recentstore=None
    remote_client=None
    use_remote_client=False
    param_client={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_server={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_node={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}


    cert_hash=None
    #start_url_hash=(None,None)
    _old_serverurl=""
    
    def __init__(self,_links):
        self.links=_links
        logging.Handler.__init__(self)
        Gtk.Application.__init__(self)
        self.sslcont=default_sslcont()
        self.builder=Gtk.Builder()
        self.builder.set_application(self)
        self.builder.add_from_file(sharedir+"gui/gtkclientmain.ui")
        self.builder.connect_signals(self)
        
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.win=self.builder.get_object("mainwin")
        self.localview=self.builder.get_object("localview")
        self.localstore=self.builder.get_object("localstore")
        self.recentview=self.builder.get_object("recentview")
        self.recentstore=self.builder.get_object("recentstore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        
        col0renderer=Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("Category", col0renderer, text=0)
        self.localview.append_column(col0)
        col1renderer=Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("Name", col1renderer, text=1)
        self.localview.append_column(col1)
        
        recentcolrenderer=Gtk.CellRendererText()
        recentcol = Gtk.TreeViewColumn("Recent", recentcolrenderer, text=0)
        self.recentview.append_column(recentcol)
        
        # self.init_storage()

    def init_storage(self):
        _storage=self.do_requestdo("listnametypes")
        if _storage[0]==False:
            return
        lstore=self.builder.get_object("localstore")
        for elem in _storage[1]:
            if elem[1]=="server":
                lstore.append(("Server",elem[0],elem[1]))
                #self.hashes[elem[1]]=("Server",elem[0])
                #self.do_requestdo("")
                #for elem2 in 
                serverlist.append((elem[0],))
                
            else:
                lstore.append(("Friends",elem[0],elem[1]))

    #ugly
    """def do_request(self,requeststr, parse=-1):
        clienturl=self.builder.get_object("clienturl").get_text().strip().rstrip()
        params=""
        for elem in ["certhash","certname"]:
            if self.param_node[elem] is not None:
                params="{}&{}".format(params,self.param_node[elem])

        if len(params)>0 and params[0] in ["?","&"]:
            params="?"+params[1:]
        try:
            temp=client.client_client.__dict__["do_request"](self,clienturl,requeststr+params,self.param_client,usecache=False,forceport=False)
        except AddressFail:
            #logging.error(requeststr)
            return (False, "address failed")
        except Exception as e:
            if "tb_frame" in e.__dict__:
                st=str(e)+"\n\n"+str(traceback.format_tb(e))
            else:
                st=str(e)

            logging.error(st)
            return (False, e)
        if temp[0]==False:
            return temp
        if parse==-1:
            rest=[]
            temp1=temp[1].split("\n")
        elif parse==0:
            rest=[temp[1]]
            temp1=[]
        else:
            temp1=temp[1].split("\n",parse)
            if len(temp1)>2:
                rest=[temp1[-1],]
                temp1=temp1[:-1]
            else:
                return (False,"arglength")
        _finish1=[]
        #TODO: empty,[] causes artifact
        for elem in temp1:
            if elem=="%":
                _finish1+=[None,]
                continue
                
            _temp2=[]
            for elem2 in elem.split("/"):
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
        
        _finish1+=rest
        #remove array if just one element
        if len(_finish1)==1:
            _finish1=_finish1[0]
        #remove trailing "" element
        elif _finish1[0]=="":
            _finish1=_finish1[1:]
        #temp[0]==True
        return (temp[0],_finish1,temp[2],temp[3])"""
        
    def do_requestdo(self,action,*requeststrs,parse=-1):
        if self.use_remote_client==False:
            return self.links["client"].__all__[action](*requeststrs)
        """else:
            temp="/do/{}".format(action)
            for elem in requeststrs:
                temp="{}/{}".format(temp,elem)
            return self.do_request(temp,parse)"""

    """def do_requestdirect(self,*requeststrs):
        _treqstr=""
        for elem in requeststrs:
            _treqstr="{}/{}".format(_treqstr,elem)
        #serverurl=self.builder.get_object("servercomboentry").get_text().strip().rstrip()
        try:
            return client.client_client.__dict__["do_request"](self,serverurl,_treqstr,self.param_node,usecache=False,forceport=False)
        except Exception as e:
            if "tb_frame" in e.__dict__:
                    st="{}\n\n{}".format(e,traceback.format_tb(e))
                else:
                    st=str(e)
            logging.error(st)
            return (False,)"""

    def pushint(self):
        time.sleep(5)
        #self.messagecount-=1
        self.statusbar.pop(self.messageid)

    def pushmanage(self,*args):
          #self.messagecount+=1
          #if self.messagecount>1:
          self.sb=threading.Thread(target=self.pushint)
          self.sb.daemon = True
          self.sb.start()

    #def handle(self,record):
    #self.statusbar.push(self.messageid,record)
    ###logging handling
    def emit(self, record):
        self.backlog+=[record,]
        if len(backlog)>200:
            self.backlog=self.backlog[200:]
        self.statusbar.push(messageid, record.message)
        self.pushmanage()
    
    def gtkretrieve_server(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        



    def gtkclose(self,*args):
        global run
        run=False


class gtk_client_init(client.client_init):

    def __init__(self,confm,pluginpathes):
        self.config_path=confm.get("config")
        _cpath="{}{}{}".format(self.config_path,os.sep,"client")
        init_config_folder(self.config_path,"client")
        
        if check_certs(_cpath+"_cert")==False:
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logging.debug("Certificate generation complete")
        
        client.client_init.__init__(self,confm,pluginpathes)
            
        #_client="localhost:{}".format(self.links["server"].socket.getsockname()[1])
        logging.debug("start server")
        self.serve_forever_nonblock()
        logging.debug("start gtkclient")
        self.links["gtkclient"]=gtkclient_main(self.links)
        

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
    
    clargs=client.client_args.copy()
    pluginpathes=["{}{}plugins".format(sharedir,os.sep)]
    
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
                    clargs[tparam[0]]=""
                    continue
                if tparam[0]in ["pluginpath","pp"]:
                    pluginpathes+=[tparam[1],]
                    continue
                clargs[tparam[0]]=tparam[1]
                
    
    
    configpath=clargs["config"]
    configpath=path.expanduser(configpath)
    if configpath[-1]==os.sep:
        configpath=configpath[:-1]
    clargs["config"]=configpath
    pluginpathes.insert(1,"{}{}plugins".format(configpath,os.sep))
    
    os.makedirs("{}{}config".format(configpath,os.sep),0o750,True)
    os.makedirs("{}{}config{}plugins".format(configpath,os.sep,os.sep),0o750,True)
    confm=configmanager("{}{}config{}{}".format(configpath,os.sep,os.sep,"clientgtkgui.conf"))
    confm.update(dclargs,clargs)
    
    client.client_handler.webgui=False
    
    config_path=path.expanduser(clargs["config"])
    if config_path[-1]==os.sep:
        config_path=config_path[:-1]
    
    plugins_config="{}{}config{}plugins".format(configpath,os.sep,os.sep)
    
    if confm.getb("noplugins")==False:
        pluginm=pluginmanager(pluginpathes,plugins_config)
        if confm.getb("webgui")!=False:
            pluginm.interfaces+=["web",]
        if confm.getb("cmd")!=False:
            pluginm.interfaces+=["cmd",]
    else:
        pluginm=None
    
    #logging.debug("start client")
    cm=gtk_client_init(confm,pluginm)
    
    if confm.getb("noplugins")==False:
        pluginm.init_plugins()
    
    
    """if confm.getb("cmd")!=False:
        logging.debug("start server")
        cm.serve_forever_nonblock()
        logging.debug("start console")
        cm.cmd()
    else:
        logging.debug("start server")
        cm.serve_forever_block()"""
    logging.debug("enter mainloop")
    while run==True:
        Gtk.main_iteration_do(True)
    sys.exit(0)
