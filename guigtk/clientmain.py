#! /usr/bin/env python3

import logging
import os
import time, threading

from gi.repository import Gtk,Gdk #,Pango
from guigtk.clientinfo import gtkclient_info
from guigtk.clientnode import gtkclient_node
from guigtk.clientserver import gtkclient_server
from guigtk.clientservice import gtkclient_remoteservice
#from gui.gtk.guicommon import run # gtkguinode

from common import init_config_folder, check_certs,default_sslcont, sharedir, \
init_config_folder, generate_certs, isself, default_sslcont

#check_hash, server_port, dhash, scnparse_url, AddressFail

import client

client.client_handler.webgui=False

messageid=0
run=True

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
        self.builder.add_from_file(sharedir+"guigtk/clientmain.ui")
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
        recentcolrenderer2=Gtk.CellRendererText()
        recentcol2 = Gtk.TreeViewColumn("Url", recentcolrenderer2, text=0)
        self.recentview.append_column(recentcol2)
        
        # self.init_storage()

    def init_storage(self):
        _storage=self.do_requestdo("listnametypes")
        if _storage[0]==False:
            return
        lstore=self.builder.get_object("localstore")
        serverlist=self.builder.get_object("serverlist")
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
        if len(self.backlog)>200:
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
        if self.curnode is not None and self.curnode[0]!="This client":
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
            self.curnode=("This client",_address,_name,_hash)
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
                name=serverurl[:20]
            elif temp[0] is isself:
                name="Own server"
            else:
                name=temp[0]
            gtkclient_info(self.links,serverurl,tdparam,name)

        


    
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
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_info(self.links,self.curnode[1],tdparam,self.curnode[0])
            
    def select_recent(self,*args):
        pass
    
    def listservices(self,*args):
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
    
    def manageservices(self,*args):
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


class gtkclient_init(client.client_init):

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

def do_gtkiteration():
    
    logging.debug("enter mainloop")
    while run==True:
        Gtk.main_iteration_do(True)
