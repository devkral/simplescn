#! /usr/bin/env python3
import logging
import signal
import sys
import os
import time,threading
import traceback#threading,
from os import path
from gi.repository import Gtk,Gdk,Pango
#,Gio


import client
from client import default_client_args as dclargs

from common import default_configdir,init_config_folder,check_name,check_certs,generate_certs,\
sharedir,isself,default_sslcont,dhash,AddressFail,\
scnparse_url,server_port,check_hash,configmanager,pluginmanager
#VALError

messageid=0

class gtkclient_template(Gtk.Builder):
    #builder=None
    links=None
    win=None
    dparam=None
    address=None
    #autoclose=0 #closes window after a timeperiod
    
    def __init__(self,_file,links,_address,dparam,objectlist=None):
        Gtk.Builder.__init__(self)
        self.links=links
        self.dparam=dparam
        self.address=_address
        
        self.set_application(links["gtkclient"])
        if objectlist is None:
            self.add_from_file(_file)
        else:
            self.add_objects_from_file(_file,objectlist)

    def do_requestdo(self,action,*requeststrs,parse=-1):
        requeststrs+=(self.dparam,)
        return self.links["gtkclient"].do_requestdo(action,*requeststrs,parse=parse)
    
    def close(self,*args):
        self.win.destroy()
        self.links["gtkclient"].remove_window(self.win)
        del self

class gtkclient_node(gtkclient_template):
    
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"gui/gtkclientnode.ui",links,_address,dparam)
        self.win=self.get_object("nodewin")
        self.win.set_title(name)
        
        self.update()
    
    def update(self,*ars):
        pass
    
    def update_actions(self):
        pass
        
    
    def activate_action(self,*args):
        pass
    
        
    
class gtkclient_server(gtkclient_template):
    isregistered=False
    
    def visible_func (self,_model,_iter,_data):
        _entry=self.get_object("servernodeentry")
        _val=_entry.get_text()
        if _val==_model[_iter][3][:len(_val)]:
            return True
        else:
            return False
    
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"gui/gtkclientserver.ui",links,_address,dparam)
        self.win=self.get_object("serverwin")
        self.filter=self.get_object("snodefilter")
        view=self.get_object("servernodeview")
        col0renderer=Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("state", col0renderer, text=0)
        #col0.props.align_set = True
        #col0.props.alignment=Pango.Alignment.CENTER
        view.append_column(col0)
        col1renderer=Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("Name", col1renderer, text=1)
        view.append_column(col1)
        col2renderer=Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Hash", col2renderer, text=2)
        view.append_column(col2)
        
        self.win.set_title(name)
        
        self.filter.set_visible_func(self.visible_func)
        
        self.connect_signals(self)
        self.update()
    
    def update(self,*args):
        namestore=self.get_object("servernodelist")
        registerb=self.get_object("registerbutton")
        self.isregistered=False
        namestore.clear()
        _names=self.do_requestdo("listnames",self.address)
        if _names[0]==False:
            logging.error(_names[1])
            return
        for elem in _names[1]:
            if elem[2] is None:
                namestore.append(("remote",elem[0],elem[1],"{}/{}".format(elem[0],elem[1])))
            elif elem[2] is isself:
                self.isregistered=True
                namestore.append(("isself",elem[0],elem[1],"{}/{}".format(elem[0],elem[1])))
            else:
                namestore.append(("local",elem[0],elem[1],"{}/{}".format(elem[0],elem[1])))
        if self.isregistered==False:
            registerb.set_label("Register")
        else:
            registerb.set_label("Update Address")
            

    
    def update_plugins(self,*args):
        pass
    
    def activate_action(self,*args):
        pass
    
    
    def snode_get(self,*args):
        _entry=self.get_object("servernodeentry")
        val=_entry.get_text()
        if val=="" or val.find("/")==-1:
            return
        _name,_hash=_entry.get_text().split("/",1)
        _node=self.do_requestdo("get",self.address,_name,_hash)
        if _node[0]==False:
            return
        
        self.links["gtkclient"].set_curnode("{}:{}".format(*_node[1]),_name,_hash)
        self.close()
        
    def snode_activate(self,*args):
        view=self.get_object("servernodeview")
        _entry=self.get_object("servernodeentry")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _entry.set_text(_sel[0][_sel[1]][0])
        self.snode_get()
        
        
    
    def snode_select(self,*args):
        view=self.get_object("servernodeview")
        _entry=self.get_object("servernodeentry")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _entry.set_text(_sel[0][_sel[1]][3])
        
    
    def snode_filter(self,*args):
        self.filter.refilter()
    
    def register(self,*args):
        namestore=self.get_object("servernodelist")
        res=self.do_requestdo("register",self.address)
        if res[0]==False:
            logging.error(res[1])
        if self.isregistered==False:
            self.isregistered=True
            namestore.prepend((self.links["client_server"].name,self.links["client"].cert_hash,"This client","{}/{}".format(self.links["client_server"].name,self.links["client"].cert_hash)))
            registerb.set_label("Update Address")

class gtkclient_info(gtkclient_template):
    name=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"gui/gtkclientmain.ui",links,_address,dparam,["infowin",])
        self.name=name
        #self.get_object("col1").set_orientation(Gtk.Orientation.VERTICAL)
        col1=self.get_object("col1")
        col2=self.get_object("col2")
        self.win=self.get_object("infowin")
        self.win.set_visible(True)
        self.win.set_title(name)
        self.update()
        
    def update(self):
        self.get_object("addressl").set_text(self.address)
        self.get_object("infonamel").set_text(self.name)
        if self.dparam["certhash"] is not None:
            self.get_object("hashl").set_text(self.dparam["certhash"])
        else:
            self.get_object("hashl").set_text("<None>")
        
        
    
        #_info=self.do_requestdo("info",self.address,parse=2)
        #if _info[0]==True:
        #    pass
    
    def col1_entry(self,name,value):
        pass
        
        
        
    def col2_entry(self,name,value):
        pass
    

class gtkclient_main(logging.NullHandler,Gtk.Application):
    links=None

    curnode=None
    
    builder=None
    clip=None
    win=None
    backlog=[]
    statusbar=None
    localview=None
    localstore=None
    recentview=None
    recentstore=None
    recentcount=0
    remote_client=None
    use_remote_client=False
    #param_client={"certname":None,"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
    param_server={"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None}
    param_node={"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None}
    

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
        if True: #self.use_remote_client==False:
            return client.client_client.__dict__[action](self.links["client"],*requeststrs)
            #self.links["client"].__dict__[action](*requeststrs)
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
    
    def _verifyserver(self,serverurl):
        _veri=self.builder.get_object("veristateserver")
        
        _hash=self.do_requestdo("ask",serverurl,self.param_server)
        if _hash[0]==False:
            _veri.set_text("")
            return None
            
        if _hash[1][0] is None:
            _veri.set_text("Unknown server")
        elif _hash[1][0] is isself:
            _veri.set_text("This client")
        else:
            _veri.set_text("Verified as:\n{}".format(_hash[1][0]))
        return _hash[1]
        
    def veristate_server(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        self._verifyserver(serverurl)
    
    def set_curnode(self,_address,_name,_hash):
        if self.curnode is not None and self.curnode[0] is not isself:
            if self.recentcount<20:
                self.recentcount+=1
                self.recentstore.prepend(self.curnode)
            else:
                self.recentstore.prepend(self.curnode)
                self.recentstore.remove(self.recentstore.iter_n_children(20))
                
        cnode=self.builder.get_object("curnode")
        cnodeorigin=self.builder.get_object("nodeorigin")
        _ask=self.do_requestdo("ask",_address,self.param_server)
        if _ask[0]==False:
            cnodeorigin.set_text("")
            cnode.set_text("invalid")
            self.curnode=None
        elif _ask[1][0] is None:
            cnodeorigin.set_text("remote:")
            cnode.set_text(_name)
            self.curnode=(_name,_address,_name,_hash)
        elif _ask[1][0] is isself:
            cnodeorigin.set_text("")
            cnode.set_text("This client")
            self.curnode=(isself,_address,_name,_hash)
            #self.curnode=(_name,_address,_name,_hash)
        else:
            cnodeorigin.set_text("verified:")
            cnode.set_text(_ask[1][0])
            self.curnode=(_ask[1][0],_address,_name,_hash)
        
        
        
    def server_info(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        temp=self._verifyserver(serverurl)
        tdparam=self.param_server.copy()
        if temp is not None:
            tdparam["certhash"]=temp[1]
            if temp[0] is None:
                gtkclient_info(self.links,serverurl,tdparam)
            elif temp[0] is isself:
                gtkclient_info(self.links,serverurl,tdparam,"This client")
            else:
                gtkclient_info(self.links,serverurl,tdparam,temp[0])

        else:
            gtkclient_info(self.links,serverurl,tdparam)
        


    
    def retrieve_server(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        temp=self._verifyserver(serverurl)
        if temp is None:
            return
        tdparam=self.param_server.copy()
        tdparam["certhash"]=temp[1]
        if temp[0] is None:
            name=serverurl[:20]
        elif temp[0] is isself:
            name="Own server"
        else:
            name=temp[0]
        gtkclient_server(self.links,serverurl,tdparam,name)
        
    
    #### node actions ####
    def addnodehash(self,*args):
        pass
    
    def delnodehash(self,*args):
        pass
    
    def enternode(self,*args):
        pass
    
    def opennode(self,*args):
        pass
        
    def infonode(self,*args):
        #serverurl=self.builder.get_object("servercomboentry").get_text()
        tdparam=self.param_node.copy()
        temp=None
        if temp is not None:
            tdparam["certhash"]=temp[1]
            gtkclient_info(self.links,nodeurl,tdparam,temp[0])
        else:
            gtkclient_info(self.links,nodeurl,tdparam)
            
    def select_recent(self,*args):
        pass
        
    #### server actions ####
    
    def addserverhash(self,*args):
        temp=self._verifyserver(serverurl)
        if temp is None:
            #
            return
        if temp[0] is not None:
            return
    
    def delserverhash(self,*args):
        pass
        
    
    
    
    #### client actions ####
    
    def useremoteclient(self,*args):
        pass
        
    
    #### misc actions ####
    
    def debugme(self,*args):
        pass
        
    def cmdmenu(self,*args):
        pass
        
    def aboutme(self, args):
        pass
        
    def select_local(self,*args):
        pass
        
    def client_help(self, args):
        pass
        
    def close(self,*args):
        global run
        run=False
        self.win.destroy()


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
