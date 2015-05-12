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
init_config_folder, generate_certs, isself, default_sslcont,check_hash, scnparse_url,AddressEmptyFail

#check_hash, server_port, dhash, scnparse_url, AddressFail

import client

client.client_handler.webgui=False

messageid=0
run=True



class gtkclient_main(logging.NullHandler,Gtk.Application):
    links=None

    curnode=None
    curlocal=None
    
    builder=None
    clip=None
    win=None
    backlog=[]
    statusbar=None
    
    localstore=None
    serverlist_dic=[]
    
    recentstore=None
    recentcount=0
    remote_client=None
    #use_remote_client=False
    
    debugwin=None
    cmdwin=None
    clientwin=None
    debug_wintoggle=None
    cmd_wintoggle=None
    client_wintoggle=None
    
    remoteclient_url=""
    remoteclient_hash=""
    use_localclient=True
    param_client={"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":True}
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
        self.localstore=self.builder.get_object("localstore")
        self.recentstore=self.builder.get_object("recentstore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        
        recentview=self.builder.get_object("recentview")
        localview=self.builder.get_object("localview")
        
        self.debugwin=self.builder.get_object("debugwin")
        self.cmdwin=self.builder.get_object("cmdwin")
        self.clientwin=self.builder.get_object("clientdia")
        self.mswin=self.builder.get_object("manageserviceswin")
        self.addentitydia=self.builder.get_object("addentitydia")
        self.delentitydia=self.builder.get_object("delentitydia")
        self.delnodedia=self.builder.get_object("delnodedia")
        self.managehashdia=self.builder.get_object("managehashdia")
        self.enternodedia=self.builder.get_object("enternodedia")
        
        
        self.debug_wintoggle=self.builder.get_object("debugme")
        self.cmd_wintoggle=self.builder.get_object("cmdme")
        self.client_wintoggle=self.builder.get_object("useremoteclient")
        
        col0 = Gtk.TreeViewColumn("Nodes", Gtk.CellRendererText(), text=0)
        localview.append_column(col0)
        
        recentcol = Gtk.TreeViewColumn("Recent", Gtk.CellRendererText(), text=0)
        recentview.append_column(recentcol)
        recentcol2 = Gtk.TreeViewColumn("Url", Gtk.CellRendererText(), text=1)
        recentview.append_column(recentcol2)
        
        serviceview=self.builder.get_object("localserviceview")
        servicecol = Gtk.TreeViewColumn("Service", Gtk.CellRendererText(), text=0)
        serviceview.append_column(servicecol)
        servicecol2 = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=1)
        serviceview.append_column(servicecol2)
        
        
        
        hview=self.builder.get_object("hashview")
        rview=self.builder.get_object("refview")
        
        hcol1= Gtk.TreeViewColumn("Hash", Gtk.CellRendererText(),text=0)
        
        rcol1= Gtk.TreeViewColumn("Reference", Gtk.CellRendererText(),text=0)
        rcol2= Gtk.TreeViewColumn("Type", Gtk.CellRendererText(),text=1)
        
        hview.append_column(hcol1)
        rview.append_column(rcol1)
        rview.append_column(rcol2)
        
        self.localstore=self.builder.get_object("localstore")
        
        self.debugwin.connect('delete-event',self.close_debug)
        self.cmdwin.connect('delete-event',self.close_cmd)
        self.clientwin.connect('delete-event',self.close_clientdia)
        self.mswin.connect('delete-event',self.close_manages)
        self.addentitydia.connect('delete-event',self.close_addentitydia)
        self.delentitydia.connect('delete-event',self.close_delentitydia)
        self.delnodedia.connect('delete-event',self.close_delnodedia)
        self.managehashdia.connect('delete-event',self.close_managehashdia)
        self.enternodedia.connect('delete-event',self.close_enternodedia)
        
        
        #overstore.append("Unknown",unstore)
        
        
        #self.clientwin.connect('delete-event',self.close_client)
        
        self.update_storage()

    def update_storage(self):
        _storage=self.do_requestdo("listnodenametypes",self.param_client)
        if _storage[0]==False:
            return
        
        self.localstore.clear()
        self.serverit=self.localstore.insert_with_values(None,-1,[0,],["Server",])
        self.server_dic=[]
        self.friendit=self.localstore.insert_with_values(None,-1,[0,],["Friend",])
        self.friend_dic=[]
        self.unknownit=self.localstore.insert_with_values(None,-1,[0,],["Unknown",])
        self.unknown_dic=[]
        self.emptyit=self.localstore.insert_with_values(None,-1,[0,],["Empty",])
        self.empty_dic=[]
        
        #serverlist=self.builder.get_object("serverlist")
        #serverlist.clear()
        for elem in _storage[1]:
            if elem[1] is None:
                self.empty_dic+=[elem[0],]
                self.localstore.insert_with_values(self.emptyit,-1,[0,],[elem[0],])
            
            elif elem[1]=="server":
                self.server_dic+=[elem[0],]
                self.localstore.insert_with_values(self.serverit,-1,[0,],[elem[0],])
            elif elem[1]=="client":
                self.friend_dic+=[elem[0],]
                self.localstore.insert_with_values(self.friendit,-1,[0,],[elem[0],])
            else:
                self.unknown_dic+=[elem[0],]
                self.localstore.insert_with_values(self.unknownit,-1,[0,],[elem[0],])
        
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
        servlist=self.builder.get_object("serverlist")
        if self._verifyserver(serverurl) is not None:
            servlist.append(())
    
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
    def addnodehash_intern(self,_node,_hash,_type=""):
        nodee=self.builder.get_object("anameentry")
        hashe=self.builder.get_object("ahashentry")
        typee=self.builder.get_object("atypeentry")
        
        nodee.set_text(_node)
        hashe.set_text(_hash)
        typee.set_text(_type)
        
        self.addnodedia.show()
        self.addnodedia.grab_focus()
    
    def addnodehash(self,*args):
        view=self.builder.get_object("recentstore")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name=_sel[0][_sel[1]][2]
        _hash=_sel[0][_sel[1]][3]
        addnodehash_intern(_name,_hash)
    
    def delnodehash(self,*args):
        view=self.builder.get_object("recentstore")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name=_sel[0][_sel[1]][2]
    
    
    def enternode(self,*args):
        self.builder.get_object("enternodeurl").set_text("")
        self.builder.get_object("enternodehash").set_text("")
        self.enternodedia.show()
        self.enternodedia.grab_focus()
    
    def enternode_confirm(self,*args):
        tparam=self.param_node.copy()
        _address=self.builder.get_object("enternodeurl").get_text().strip(" ").rstrip(" ")
        _hash=self.builder.get_object("enternodehash").get_text().strip(" ").rstrip(" ")
        if _hash=="":
            ret=self.do_requestdo("gethash",_address,tparam)
            if ret[0]==False:
                logging.info(ret[1])
                return
            _hash=ret[1][0]
        if check_hash(_hash)==False:
            logging.info("hash wrong")
            return
        if _address=="":
            logging.info("address wrong")
            return
        tparam["certhash"]=_hash
        ret=self.do_requestdo("info",tparam)
        if ret[0]==False:
            logging.error(ret[1])
            return
        self.set_curnode(_address,ret[1][1],_hash)
        self.close_enternode()
    
    def opennode(self,*args):
        tdparam=self.param_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_node(self.links,self.curnode[1],tdparam,self.curnode[0])
        
    def infonode(self,*args):
        #serverurl=self.builder.get_object("servercomboentry").get_text()
        tdparam=self.param_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_info(self.links,self.curnode[1],tdparam,self.curnode[0])
            
    def activate_recent(self,*args):
        view=self.builder.get_object("recentstore")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _address=_sel[0][_sel[1]][1]
        _name=_sel[0][_sel[1]][2]
        _hash=_sel[0][_sel[1]][3]
        self.set_curnode(_address,_name,_hash)
    
    def listservices(self,*args):
        tdparam=self.param_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_remoteservice(self.links,self.curnode[1],tdparam,self.curnode[0])
    
    
    
    #### server actions ####
    
    def addserverhash(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        view=self.builder.get_object("localview")
        _sel=view.get_selection().get_selected()
        temp=self._verifyserver(serverurl)
        if temp is not None:
            _hash=temp[1]
        else:
            return
        if temp[0] is not None:
            logging.debug("Already exists")
            return
        if _sel[1] is not None:
            _name=_sel[0][_sel[1]][3]
        else:
            _name=""
        self.addnodehash_intern(_hash,_name,"server")
    
        
    
    
    #### client actions ####
    
    def clientme(self,*args):
        self.builder.get_object("clienturl").set_text(self.remoteclient_url)
        self.builder.get_object("clienthash").set_text(self.remoteclient_hash)
        self.builder.get_object("uselocal").set_active(self.use_localclient)
        
        self.clientwin.show()
        self.clientwin.grab_focus()
    
    def client_confirm(self,*args):
        clurl=self.builder.get_object("clienturl")
        clhash=self.builder.get_object("clienthash")
        ulocal=self.builder.get_object("uselocal")
        if ulocal.get_active()!=True:
            if clurl.get_text()=="":
                #clurl.
                return
            if check_hash(clhash.get_text()==False):
                return
        self.remoteclient_url=clurl.get_text()
        self.remoteclient_hash=self.builder.get_object("clienthash").get_text()
        self.use_localclient=self.builder.get_object("uselocal").get_active()
        self.close_client()
        
    def client_localtoggle(self,*args):
        toggle=self.builder.get_object("uselocal")
        clurl=self.builder.get_object("clienturl")
        clhash=self.builder.get_object("clienthash")
        if toggle.get_active()==True:
            clurl.set_sensitive(False)
            clhash.set_sensitive(False)
        else:
            clurl.set_sensitive(True)
            clhash.set_sensitive(True)
    
    
    def update_services(self,*args):
        localservicelist=self.builder.get_object("localservicelist")
        localservicelist.clear()
        but=self.builder.get_object("deleteserviceb")
        but.hide()
        services=self.do_requestdo("listservices",self.param_client)
        if services[0]==False:
            return
        for elem in services[1]:
            localservicelist.append((elem[0],elem[1]))
        
    def add_service(self,*args):
        localservicelist=self.builder.get_object("localservicelist")
        servicee=self.builder.get_object("newservicenameentry")
        porte=self.builder.get_object("newserviceportentry")
        service=servicee.get_text().strip(" ").rstrip(" ")
        port=porte.get_text().strip(" ").rstrip(" ")
        if service=="":
            logging.debug("service invalid")
            return
        if port=="" or port.isdecimal()==False:
            logging.debug("port invalid")
            return
        ret=self.do_requestdo("registerservice",service,port,self.param_client)
        if ret[0]==False:
            logging.debug(ret[1])
            return
        servicee.set_text("")
        porte.set_text("")
        
        localservicelist.append((service,port))
    def sel_service(self,*args):
        view=self.builder.get_object("localserviceview")
        but=self.builder.get_object("deleteserviceb")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            but.hide()
        else:
            but.show()
    def del_service(self,*args):
        view=self.builder.get_object("localserviceview")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service=_sel[0][_sel[1]][0]
        if service=="":
            return
        ret=self.do_requestdo("delservice",service,self.param_client)
        if ret[0]==False:
            return
        self.update_services()
        
    def manageservices(self,*args):
        self.update_services()
        self.mswin.show()
        self.mswin.grab_focus()
    
    #### misc actions ####
    
    def debugme(self,*args):
        if self.debug_wintoggle.get_active()==True:
            self.debugwin.show()
            self.debugwin.grab_focus()
        else:
            self.debugwin.hide()
        
    def cmdme(self,*args):
        if self.cmd_wintoggle.get_active()==True:
            self.cmdwin.show()
            self.cmdwin.grab_focus()
            
        else:
            self.cmdwin.hide()
            
        
    def aboutme(self, args):
        pass
        
    def checkserver(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        temp=self.do_requestdo("listhashes",_name,self.param_client)
        if temp[0]==False:
            logging.debug("Exist?")
                
            return
        try:
            serverurl="{}:{}".format(*scnparse_url(serverurl))
        except AddressEmptyFail:
            logging.debug("Address Empty")
            return
        if self.do_requestdo("prioty_direct",serverurl,self.param_server)==False:
            logging.debug("Server address invalid")
            return
        for elem in temp[1]:
            if elem[1]=="unknown":
                self.do_requestdo("check",serverurl,_name,elem[0],self.param_server)
        self.update_storage()
        
    def activate_local(self,*args):
        localview=self.builder.get_object("localview")
        serverurl=self.builder.get_object("servercomboentry").get_text()
        _sel=localview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name=_sel[0][_sel[1]][0]
        
        parentit=_sel[0].iter_parent(_sel[1])
        if parentit is None:
            self.addentity()
            return
        _type=_sel[0][parentit][0]
        
        if _type=="Server":
            self.curlocal=("server",_name)
        elif _type=="Friend":
            self.curlocal=("client",_name)
        else:
            self.curlocal=("unknown",_name)
        self.leave_active=True
        self.update_hashes()
        self.managehashdia.set_title(_name)
        self.managehashdia.show()
        
    def update_hashes(self,*args):
        temp=self.do_requestdo("listhashes",self.curlocal[1],self.param_client)
        hashlist=self.builder.get_object("hashlist")
        hashlist.clear()
        if temp[0]==False:
            logging.debug("Exist?")
        for elem in temp[1]:
            if elem[1] is None:
                pass
            elif elem[1]==self.curlocal[0]:
                hashlist.append((elem[0],))
        
    def select_hash(self,*args):
        view=self.builder.get_object("hashview")
        _sel=view.get_selection().get_selected()
        reflist=self.builder.get_object("reflist")
        reflist.clear()
        if _sel[1] is None:
            return
        self.update_refs()
        
    def update_refs(self,*args):
        hview=self.builder.get_object("hashview")
        _sel=hview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _hash=_sel[0][_sel[1]][0]
    
        temp=self.do_requestdo("getreferences",self.curlocal[1],_hash,self.param_client)
        reflist=self.builder.get_object("reflist")
        reflist.clear()
        if temp[0]==False:
            logging.debug("Exist?")
            return
        for elem in temp[1]:
            reflist.append((elem[0],elem[1]))
        
    def client_help(self, args):
        pass
    
    def addentity(self,*args):
        self.builder.get_object("addentityentry").set_text("")
        
        self.addentitydia.show()
        
    def addentity_confirm(self,*args):
        addentity=self.builder.get_object("addentityentry")
        _entity=addentity.get_text()
        res=self.do_requestdo("addentity",_entity,self.param_client)
        if res[0]==True:
            self.addentitydia.hide()
            self.empty_dic+=[_entity,]
            self.localstore.insert_with_values(self.emptyit,-1,[0,],[_entity,])
            
    def delentity(self,*args):
        self.builder.get_object("showentity")
        self.delentitydia.show()
        
    def delentity_confirm(self,*args):
        res=self.do_requestdo("delentity",self.curlocal[1],self.param_client)
        if res[0]==True:
            self.update_storage()
            self.delentitydia.hide()
            
    def addhash_confirm(self,*args):
        addhashentry=self.builder.get_object("addhashentry")
        if addhashentry.is_visible()==False:
            if self.curnode is not None:
                addhashentry.set_text(self.curnode[3])
            else:
                addhashentry.set_text("")
            addhashentry.set_visible(True)
            return
            
        _hash=addhashentry.get_text()
        if check_hash(_hash)==False:
            return
        res=self.do_requestdo("addhash",self.curlocal[1],_hash,self.param_client)
        if res[0]==True:
            addhashentry.hide()
            self.update_hashes()
    
    def delhash_confirm(self,*args):
        hview=self.builder.get_object("hashview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        res=self.do_requestdo("delhash",self.curlocal[1],_hash,self.param_client)
        if res[0]==True:
            self.delhashdia.hide()
            self.update_hashes()
        #self.update()
        
    def addreference_confirm(self,*args):
        addrefentry=self.builder.get_object("addrefentry")
        if addrefentry.is_visible()==False:
            addrefentry.set_text("")
            addrefentry.set_visible(True)
            return
        hview=self.builder.get_object("hashview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        
        _ref=addrefentry.get_text()
        tparam=self.param_client.copy()
        tparam["certhash"]=_hash
        
        if self.curlocal[0] in ["Server",]:
            #try:
            #    temp=scnparse_url(_ref)
            #except AddressEmptyFail:
            #    return
            _reftype="ipu" #TODO: be more specific
        elif self.curlocal[0]=="Friend":
            _reftype="name"
        else:
            #return
            _reftype="test"
        
        res=self.do_requestdo("addreference",self.curlocal[1],_hash,_ref,_reftype,tparam)
        if res[0]==True:
            addrefentry.hide()
            self.update_refs()
            
        
    def delreference_confirm(self,*args):
        hview=self.builder.get_object("hashview")
        rview=self.builder.get_object("refview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        _selh=hview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref=_selr[0][_selr[1]][0]
        
        res=self.do_requestdo("delreference",self.curlocal[1],_hash,_ref,self.param_client)
        if res[0]==True:
            self.delrefdia.hide()
            self.update_refs()
    
    def cmd_do(self,*args):
        cmdveri=self.builder.get_object("cmdverify")
        inp=self.builder.get_object("cmdenter")
        out=self.builder.get_object("cmdbuffer")
        dparam={"certhash":None,"cpwhash":None,"spwhash":None,"tpwhash":None,"tdestname":None,"tdesthash":None,"nohashdb":None}
        unparsed=inp.get_text().strip(" ").rstrip(" ")
        if unparsed[:5]=="hash/":
            out.insert(out.get_end_iter(),str(dhash(unparsed[6:]))+"\n")
            return
        if unparsed[:4]=="set/":
            keyvalue=unparsed[5:].split(1)
            if len(keyvalue)==1:
                out.insert(out.get_end_iter(),"invalid\n")
                return
            self.links["configmanager"].set(keyvalue[0],keyvalue[1])
            return
        if unparsed[:4]=="help":
            out.insert(out.get_end_iter(),client.cmdhelp())
            return
        pos_param=unparsed.find("?")
        if pos_param!=-1:
            parsed=unparsed[:pos_param].split("/")
            tparam=unparsed[pos_param+1:].split("&")
            for elem in tparam:
                elem=elem.split("=")
                if len(elem)==1 and elem[0]!="":
                    dparam[elem[0]]=""
                elif len(elem)==2:
                    dparam[elem[0]]=elem[1]
                else:
                    out.insert(out.get_end_iter(),"invalid key/value pair\n{}".format(elem))
                    return
                        
        else:
            parsed=unparsed.split("/")
        parsed+=[dparam,]
        try:
            func=type(self.links["client"]).__dict__[str(parsed[0])]
            resp=func(self.links["client"],*parsed[1:])
            if resp[0]==False:
                out.insert(out.get_end_iter(),"Error:\n{}\n".format(resp[1]))
            else:
                if resp[2] is None:
                    cmdveri.set_text("Unverified")
                elif resp[2] is isself:
                    cmdveri.set_text("Is own client")
                else:
                    cmdveri.set_text("Verified as: "+resp[2])
                out.insert(out.get_end_iter(),"Success:\n{}\n".format(resp[1]))
        except KeyError as e:
            out.insert(out.get_end_iter(),"Command does not exist?\n{}\n".format(parsed))
                
        except Exception as e:
            out.insert(out.get_end_iter(),"Error\ntype: {}\nparsed: {}\n".format(type(e).__name__,parsed))
        
    
    def close_debug(self,*args):
        self.debug_wintoggle.set_active(False)
        self.debugwin.hide()
        return True
    
    def close_cmd(self,*args):
        self.cmd_wintoggle.set_active(False)
        self.cmdwin.hide()
        return True
        
    def close_clientdia(self,*args):
        self.clientwin.hide()
        return True
    
    def close_manages(self,*args):
        self.mswin.hide()
        return True
    
    def close_addentitydia(self,*args):
        self.addentitydia.hide()
        return True
        
    def close_delentitydia(self,*args):
        self.delentitydia.hide()
        return True
    
    
    def close_delnodedia(self,*args):
        self.delnodedia.hide()
        return True
        
    def close_delrefdia(self,*args):
        self.delrefdia.hide()
        return True
        
    def close_managehashdia(self,*args):
        self.managehashdia.hide()
        return True
        
    leave_active=False
    def close_managehashdia_activateleave(self,*args):
        self.leave_active=True

    def close_managehashdia_deactivateleave(self,*args):
        self.leave_active=False
        
    def close_managehashdia_leave(self,*args):
        if self.leave_active==True:
            self.managehashdia.hide()
    #def close_managehashdia3(self,*args):
    
    
    def close_enternodedia(self,*args):
        self.enternodedia.hide()
        return True
    
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
