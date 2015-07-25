#! /usr/bin/env python3

import os
#,sys
#sys.path.append(os.path.dirname(__file__))


import logging

import time, threading

from gi.repository import Gtk,Gdk #,Pango
from guigtk.clientinfo import gtkclient_info
from guigtk.clientnode import gtkclient_node
from guigtk.clientserver import gtkclient_server
from guigtk.clientservice import gtkclient_remoteservice
from guigtk.clientmain_sub import services_stuff, cmd_stuff, debug_stuff
from guigtk.clientmain_managehash import hashmanagement

from client import reference_header
from common import init_config_folder, check_certs,default_sslcont, sharedir, \
init_config_folder, generate_certs, isself, default_sslcont, check_hash, \
scnparse_url, AddressEmptyFail
#, replace_logger

from common import logger
#logger=getlogger()
#init_logger()

#check_hash, server_port, dhash, AddressFail

import client

client.client_handler.webgui=False

messageid=0
run=True

implementedrefs=["surl", "url", "name"]
#,"sname"

class gtkclient_main(logging.Handler,Gtk.Application,services_stuff, cmd_stuff, debug_stuff, hashmanagement):
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
    

    clientwin=None
    client_wintoggle=None
    
    
    remoteclient_url=""
    remoteclient_hash=""
    use_localclient=True
    header_client = None
    header_server = None
    header_node = None
    

    cert_hash=None
    #start_url_hash=(None,None)
    _old_serverurl=""
    
    #
    #debugbuffer = debug_stuff.debugbuffer
    #debugview = debug_stuff.debugview
    #managehashdia = hashmanagement.managehashdia
    
    def __init__(self,_links):
        self.header_client = reference_header.copy()
        self.header_server = reference_header.copy()
        self.header_node = reference_header.copy()
        self.links=_links
        logging.Handler.__init__(self)
        Gtk.Application.__init__(self)
        self.sslcont=default_sslcont()
        self.builder=Gtk.Builder()
        self.builder.set_application(self)
        self.builder.add_from_file(os.path.join(sharedir, "guigtk", "clientmain.ui"))
        self.builder.add_from_file(os.path.join(sharedir, "guigtk", "clientmain_sub.ui"))
        self.builder.connect_signals(self)
        
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        
        self.win=self.builder.get_object("mainwin")
        self.localstore=self.builder.get_object("localstore")
        self.recentstore=self.builder.get_object("recentstore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        self.hashstatusbar=self.builder.get_object("hashstatusbar")
        
        recentview=self.builder.get_object("recentview")
        localview=self.builder.get_object("localview")
        
        debug_stuff.__init__(self)
        services_stuff.__init__(self)
        cmd_stuff.__init__(self)
        hashmanagement.__init__(self)
        
        listnodetypes=self.builder.get_object("listnodetypes")
        listnodetypes.append(("server","Server"))
        listnodetypes.append(("client","Friend"))
        listnodetypes.append(("unknown","Unknown"))
        
        
        self.clientwin=self.builder.get_object("clientdia")
        self.addentitydia = self.builder.get_object("addentitydia")
        self.delentitydia = self.builder.get_object("delentitydia")
        self.delrefdia = self.builder.get_object("delrefdia")
        self.addnodedia = self.builder.get_object("addnodedia")
        self.delnodedia = self.builder.get_object("delnodedia")
        self.enternodedia = self.builder.get_object("enternodedia")
        self.renameentitydia = self.builder.get_object("renameentitydia")
        
        self.client_wintoggle = self.builder.get_object("useremoteclient")
        
        
        addnodecombo = self.builder.get_object("addnodecombo")
        addnodecomborenderer = Gtk.CellRendererText()
        addnodecombo.pack_start(addnodecomborenderer, True)
        addnodecombo.add_attribute(addnodecomborenderer, "text", 0)
        
        
        addnodetypecombo = self.builder.get_object("addnodetypecombo")
        addnodetypecomborenderer=Gtk.CellRendererText()
        addnodetypecombo.pack_start(addnodetypecomborenderer, True)
        addnodetypecombo.add_attribute(addnodetypecomborenderer, "text", 1)
        
        col0 = Gtk.TreeViewColumn("Nodes", Gtk.CellRendererText(), text=0)
        localview.append_column(col0)
        
        recentcol = Gtk.TreeViewColumn("Recent", Gtk.CellRendererText(), text=0)
        recentview.append_column(recentcol)
        recentcol2 = Gtk.TreeViewColumn("Url", Gtk.CellRendererText(), text=1)
        recentview.append_column(recentcol2)
        
        hview=self.builder.get_object("hashview")
        rview=self.builder.get_object("refview")
        
        hcol1= Gtk.TreeViewColumn("Node", Gtk.CellRendererText(),text=0)
        
        rcol1= Gtk.TreeViewColumn("Reference", Gtk.CellRendererText(),text=0)
        rcol2= Gtk.TreeViewColumn("Type", Gtk.CellRendererText(),text=1)
        
        hview.append_column(hcol1)
        rview.append_column(rcol1)
        rview.append_column(rcol2)
        
        self.localstore=self.builder.get_object("localstore")
        
        
        
        self.clientwin.connect('delete-event',self.close_clientdia)
        
        self.addentitydia.connect('delete-event',self.close_addentitydia)
        self.delentitydia.connect('delete-event',self.close_delentitydia)
        self.delrefdia.connect('delete-event',self.close_delrefdia)
        self.addnodedia.connect('delete-event',self.close_addnodedia)
        self.delnodedia.connect('delete-event',self.close_delnodedia)
        self.enternodedia.connect('delete-event',self.close_enternodedia)
        self.renameentitydia.connect('delete-event',self.close_renameentitydia)
        self.win.connect('delete-event',self.close)
        
        self.update_storage()

    def update_storage(self):
        _storage=self.do_requestdo("listnodenametypes",self.header_client)
        if logger().check(_storage)==False:
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
            if elem[0] is None:
                logger().critical("None element as name")
                return
            if elem[1] is None:
                self.empty_dic+=[elem[0],]
                #
            
            elif elem[1]=="server":
                self.update_serverlist(elem[0])
                self.server_dic+=[elem[0],]
                self.localstore.insert_with_values(self.serverit,-1,[0,],[elem[0],])
            elif elem[1]=="client":
                self.friend_dic+=[elem[0],]
                self.localstore.insert_with_values(self.friendit,-1,[0,],[elem[0],])
            else:
                self.unknown_dic+=[elem[0],]
                self.localstore.insert_with_values(self.unknownit,-1,[0,],[elem[0],])
                
        for elem in self.server_dic+self.friend_dic+self.unknown_dic:
            if elem in self.empty_dic:
                self.empty_dic.remove(elem)

        for elem in self.empty_dic:
            self.localstore.insert_with_values(self.emptyit,-1,[0,],[elem,])
        
        localnames=self.builder.get_object("localnames")
        localnames.clear()
        localnames.append(("",))
        _names=self.do_requestdo("listnodenames",self.header_client)
        if logger().check(_names)==False:
            return
        
        for elem in _names[1]:
            localnames.append((elem,))
        
    def update_serverlist_hash(self, _hash):
        serverlist=self.builder.get_object("serverlist")
        
        _serverrefs=self.do_requestdo("getreferences",_hash,self.header_client)
        if logger().check(_serverrefs)== False:
            return
        for elem in _serverrefs[1]:
            if elem[0] not in self.serverlist_dic:
                if elem[1] == "name":
                    serverlist.append((elem[0],True))
                    self.serverlist_dic.append(elem[0])
                elif elem[1] == "url":
                    serverlist.append((elem[0],False))
                    self.serverlist_dic.append(elem[0])
                    
    def update_serverlist(self, _localname):
        _serverhashes=self.do_requestdo("listhashes",_localname,self.header_client)
        if logger().check(_serverhashes)==True:
            for _hash in _serverhashes[1]:
                if _hash[0]!="default":
                    self.update_serverlist_hash(_hash[0])

    def do_requestdo(self,action,*requeststrs):
        uselocal=self.builder.get_object("uselocal")
        if uselocal.get_active() == True:
            return self.links["client"].access_main(action, requeststrs[:-1],requeststrs[-1])
        else:
            try:
                self.links["client"].do_request(self, "127.0.0.1", "get", requeststrs[-1], body=json.dumps(requeststrs), forceport=True,requesttype="PUT")
            except Exception :
                pass
    def pushint(self):
        time.sleep(5)
        #self.messagecount-=1
        self.statusbar.pop(messageid)
        self.hashstatusbar.pop(messageid)

    def pushmanage(self,*args):
        #self.messagecount+=1
        #if self.messagecount>1:
        self.sb=threading.Thread(target=self.pushint)
        self.sb.daemon = True
        self.sb.start()

    ###logging handling
    def emit(self, record): 
        self.backlog+=[record,]
        if len(self.backlog)>200:
            self.backlog=self.backlog[200:]
        self.statusbar.push(messageid, str(record.msg))
        self.hashstatusbar.push(messageid, str(record.msg))
        
        
        st="{}\n".format(record.msg)
        if record.stack_info is not None:
            st="{}\n{}\n".format(st,record.stack_info)
        if self.debugbuffer.get_end_iter().is_start()==False:
            self.debugbuffer.insert(self.debugbuffer.get_end_iter(),"-----------------------\n")
        self.debugbuffer.insert(self.debugbuffer.get_end_iter(),"{}\n".format(st))
        self.debugbuffer.move_mark_by_name("scroll", self.debugbuffer.get_end_iter())
        scrollmark = self.debugbuffer.get_mark("scroll")
        self.debugview.scroll_to_mark(scrollmark,0.4,True,0,1)
        self.pushmanage()
    
    def _verifyserver(self,serverurl):
        _veri=self.builder.get_object("veristateserver")
        
        _hash=self.do_requestdo("ask",serverurl,self.header_server)
        if _hash[0]==False:
            _veri.set_text("")
            return None
            
        if _hash[1][0] is None:
            _veri.set_text("Unknown server")
        elif _hash[1][0] == isself:
            _veri.set_text("This client")
        else:
            _veri.set_text("Verified as:\n{}".format(_hash[1][0]))
        return _hash[1]
        
    def veristate_server(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        servlist=self.builder.get_object("serverlist")
        if self._verifyserver(serverurl) is not None:
            if serverurl not in self.serverlist_dic:
                servlist.append((serverurl,False))
                self.serverlist_dic.append(serverurl)
    
    def set_curnode(self, _clientaddress,_name,_hash,_serveraddress=None):
        if self.curnode is not None and self.curnode[0]!=isself:
            self.recentstore.prepend(self.curnode)
            if self.recentcount<20:
                self.recentcount+=1
            else:
                self.recentstore.remove(self.recentstore.iter_n_children(20))
                
        cnode=self.builder.get_object("curnode")
        cnodeorigin=self.builder.get_object("nodeorigin")
        opennodeb=self.builder.get_object("opennodeb")
        _ask=self.do_requestdo("ask",_clientaddress,self.header_server)
        if _ask[0]==False:
            cnodeorigin.set_text("")
            cnode.set_text("invalid")
            opennodeb.set_sensitive(False)
            self.curnode=None
        elif _ask[1][0] is None:
            cnodeorigin.set_text("remote:")
            cnode.set_text(_name)
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode=(_name,_clientaddress,_name,_hash,_serveraddress)
        elif _ask[1][0] == isself:
            cnodeorigin.set_text("")
            cnode.set_text("This client")
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode=(isself,_clientaddress,_name,_hash,_serveraddress)
            #self.curnode=(_name,_address,_name,_hash)
        else:
            cnodeorigin.set_text("verified:")
            cnode.set_text(_ask[1][0])
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode=(_ask[1][0],_clientaddress,_name,_hash,_serveraddress)

        
    def server_info(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        temp=self._verifyserver(serverurl)
        tdparam=self.header_server.copy()
        if temp is not None:
            tdparam["certhash"]=temp[1]
            if temp[0] is None:
                name=serverurl[:20]
            elif temp[0] == isself:
                name="Own server"
            else:
                name=temp[0]
            gtkclient_info(self.links,"{}:{}".format(*scnparse_url(serverurl)),tdparam,name)

    
    def retrieve_server(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        temp=self._verifyserver(serverurl)
        if temp is None:
            return
        tdparam=self.header_server.copy()
        tdparam["certhash"]=temp[1]
        if temp[0] is None:
            name=serverurl[:20]
        elif temp[0] == isself:
            name="Own server"
        else:
            name=temp[0]
        gtkclient_server(self.links,"{}:{}".format(*scnparse_url(serverurl)),tdparam,name)
        
    
    #### node actions ####
    def addnodehash_intern(self,_name,_hash,_type="unknown", refstoadd=()):
        addnodecombo = self.builder.get_object("addnodecombo")
        addnodehashentry = self.builder.get_object("addnodehashentry")
        addnodetypeentry = self.builder.get_object("addnodetypecombo")
        
        addnodecombo.set_active_id(_name)
        addnodehashentry.set_text(_hash)
        addnodetypeentry.set_active_id(_type)
        self._intern_refstoadd=refstoadd
        self.addnodedia.show()
        self.addnodedia.grab_focus()
    
    def addnodehash(self,*args):
        localview=self.builder.get_object("localview")
        _sel=localview.get_selection().get_selected()
        if _sel[1] is None:
            _name=""
        else:
            _name=_sel[0][_sel[1]][0]
        
        if self.curnode is None:
            self.addnodehash_intern(_name,"","client")
        else:
            if self.curnode[4] is None:
                self.addnodehash_intern(_name,self.curnode[3],"client",refstoadd=(("name",self.curnode[2])))
            else:
                self.addnodehash_intern(_name,self.curnode[3],"client",refstoadd=(("surl",self.curnode[4]),("name",self.curnode[2])))
        

    def addnodehash_confirm(self,*args):
        addnodecombo = self.builder.get_object("addnodecombo")
        addnodehashentry = self.builder.get_object("addnodehashentry")
        addnodetypecombo = self.builder.get_object("addnodetypecombo")
        
        hashlist=self.builder.get_object("hashlist")
        hashview=self.builder.get_object("hashview")
        
        _name = addnodecombo.get_active_id()
        _hash = addnodehashentry.get_text().strip(" ").rstrip(" ")
        _type = addnodetypecombo.get_active_id()
        
        if _name is None:
            return
        
        if _type == "":
            _type = "unknown"
        
        if check_hash(_hash) == False:
            logger().debug("invalid hash")
            return
        res = self.do_requestdo("addhash",_name,_hash,_type,self.header_client)
        if logger().check(res) == True:
            self.update_storage()
            if self.curlocal is not None and _type==self.curlocal[0]:
                it=hashlist.prepend((_hash,))
                hashview.get_selection().select_iter(it)
            #self.update_hashes()
            #?????TODO: DOCUMENTATION
            for elem in self._intern_refstoadd:
                self.do_requestdo("addreference",_hash,elem[1],elem[0],self.header_client)
            
            self.close_addnodedia()
        else:
            logger().error(res[1])
    
    
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
        tparam=self.header_node.copy()
        _address=self.builder.get_object("enternodeurl").get_text().strip(" ").rstrip(" ")
        _hasho=self.builder.get_object("enternodehash")
        _hash=_hasho.get_text().strip(" ").rstrip(" ")
        if _hash=="":
            ret=self.do_requestdo("gethash",_address,tparam)
            if logger().check(ret,logging.INFO)==False:
                return
            _hasho.set_text(ret[1][0])
            return
        if check_hash(_hash)==False:
            logger().info("hash wrong")
            return
        if _address=="":
            logger().info("address wrong")
            return
        tparam["certhash"]=_hash
        ret=self.do_requestdo("info",tparam)
        if logger().check(ret,logging.ERROR)==False:
            return
        self.set_curnode(_address,ret[1][1],_hash, None)
        self.close_enternodedia()
    
    def opennode(self,*args):
        tdparam=self.header_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_node(self.links,self.curnode[1],tdparam,self.curnode[0])
    
    def opennode_self(self,*args):
        tdparam=self.header_node.copy()
        ret=self.do_requestdo("show",tdparam)
        if ret[0] == True:
            tdparam["certhash"]=ret[1][1]
            gtkclient_node(self.links,"localhost:{}".format(ret[1][2]),tdparam,isself)
    
    
        
    def infonode(self,*args):
        #serverurl=self.builder.get_object("servercomboentry").get_text()
        tdparam=self.header_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_info(self.links,"{}:{}".format(*scnparse_url(self.curnode[1])),tdparam,self.curnode[0])
            
    def activate_recent(self,*args):
        view=self.builder.get_object("recentstore")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _address=_sel[0][_sel[1]][1]
        _name=_sel[0][_sel[1]][2]
        _hash=_sel[0][_sel[1]][3]
        self.set_curnode(_address,_name,_hash, None)
        
    
    
    def listservices(self,*args):
        tdparam=self.header_node.copy()
        if self.curnode is not None:
            tdparam["certhash"]=self.curnode[3]
            gtkclient_remoteservice(self.links,"{}:{}".format(*scnparse_url(self.curnode[1])),tdparam,self.curnode[0])
    
    
    
    #### server actions ####
    
    def addserverhash(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text().strip(" ").rstrip(" ")
        serverurl="{}:{}".format(*scnparse_url(serverurl))
        localview=self.builder.get_object("localview")
        
        
        temp=self._verifyserver(serverurl)
        if temp is None:
            logger().debug("Something failed")
            return
            
        if temp[0] is not None:
            logger().debug("Already exists")
            return
        _hash=temp[1]
        
        
        _sel=localview.get_selection().get_selected()
        if _sel[1] is None:
            _name = ""
        else:
            _name = _sel[0][_sel[1]][0]
        
        self.managehashdia.hide()
        serverurl.find("")
        
        self.addnodehash_intern(_name, _hash, "server",refstoadd=(("url",serverurl),))
    
        
    
    
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
        self.close_clientdia()
        
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
        
    
    #### misc actions ####

        
    def aboutme(self, args):
        pass
        
    def checkserver(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        #temp=self.do_requestdo("listnodenametypes",self.header_client)
        #if temp[0]==False:
        #    logger().debug("Exist?")
        #    return
        try:
            serverurl="{}:{}".format(*scnparse_url(serverurl))
        except AddressEmptyFail:
            logger().debug("Address Empty")
            return
        if self.do_requestdo("prioty_direct",serverurl,self.header_server)==False:
            logger().debug("Server address invalid")
            return
        #for elem in temp[1]:
        #    if elem[1]=="unknown":
        #        self.do_requestdo("check",serverurl,_name,elem[0],self.header_server)
        self.update_storage()
        
    
        
    def client_help(self, args):
        pass
    
        
    
    ##### etc
    
    def addentity(self,*args):
        self.builder.get_object("addentityentry").set_text("")
        
        self.addentitydia.show()
    
    def addentity_confirm(self,*args):
        addentity=self.builder.get_object("addentityentry")
        localnames=self.builder.get_object("localnames")
        _entity=addentity.get_text()
        res=self.do_requestdo("addentity",_entity,self.header_client)
        if res[0]==True:
            self.addentitydia.hide()
            self.empty_dic+=[_entity,]
            localnames.prepend((_entity,))
            self.localstore.insert_with_values(self.emptyit,-1,[0,],[_entity,])
            
    def delentity(self,*args):
        entity = self.builder.get_object("showentity")
        entity.set_text(self.curlocal[1])
        self.delentitydia.show()
        
    def delentity_confirm(self,*args):
        res=self.do_requestdo("delentity",self.curlocal[1],self.header_client)
        if res[0]==True:
            self.update_storage()
            self.delentitydia.hide()
    
    def delhash(self,*args):
        hview=self.builder.get_object("hashview")
        dia=self.builder.get_object("delnodedia")
        showhash=self.builder.get_object("showhash")
        referencecount=self.builder.get_object("referencecount")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        showhash.set_text(_hash)
        refsl=self.do_requestdo("getreferences",_hash,self.header_client)
        
        if refsl[0]==True:
            referencecount.set_text(str(len(refsl[1])))
        dia.show()
    
    def delhash_confirm(self,*args):
        hview=self.builder.get_object("hashview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        res=self.do_requestdo("delhash",_hash,self.header_client)
        if res[0]==True:
            self.delnodedia.hide()
            #self.update_hashes()
            self.update_storage()
        #self.update()
        
        
    
    def addrefentry_confirm(self,*args):
        updatereftb=self.builder.get_object("updatereftb")
        
        if updatereftb.get_sensitive() == False:
            self.addreference_action()
            return
        
        # path for updating
        addrefentry=self.builder.get_object("addrefentry")
        addrefb=self.builder.get_object("addrefb")
        reflist=self.builder.get_object("reflist")
        refview=self.builder.get_object("refview")
        hview = self.builder.get_object("hashview")
        
        _selr=refview.get_selection().get_selected()
        if _selr[1] is None:
            logger().debug("invalid reference selection")
            updatereftb.set_active(True)
            return
        _ref_sel=_selr[0][_selr[1]][0]
        
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            logger().debug("invalid hash selection")
            updatereftb.set_active(True)
            return
        ref_hash = _selh[0][_selh[1]][0]
        
        
        #if updatereftb.get_active() == False:
        #    addrefentry.
        #    addrefentry.set_text("{}:{}".format(_selr[0][_selr[1]][1],_selr[0][_selr[1]][0]))
        #    updatereftb.set_active(True)
        #    return
        
        _ref_entry=addrefentry.get_text().strip(" ").rstrip(" ")
        if _ref_entry=="":
            
            updatereftb.set_active(False)
            addrefb.show()
            addrefentry.hide()
            return
        
        if _ref_entry.find(":") == -1:
            logger().debug("invalid input")
            updatereftb.set_active(True)
            return
        _type, _ref=_ref_entry.split(":", 1)
        
        
        if not _type in implementedrefs:
            logger().debug("invalid type")
            updatereftb.set_active(True)
            return
        
        #if _type=="shash":
        #    ressname=self.do_requestdo("ask", _ref, self.header_client)
        #    if ressname[0]==False or ressname[1][0] is None:
        #        logger().error("invalid name")
        #        return
            
        res=self.do_requestdo("updatereference", ref_hash, _ref,_ref, _type, self.header_client)
        if res[0]==True:
            if _type in ["url", "name"]:
                self.update_storage()
            addrefb.show()
            addrefentry.hide()
            _selr[0][_selr[1]][0]=_ref
            _selr[0][_selr[1]][1]=_type
            updatereftb.set_active(False)
            
        else:
            logger().error(res[1])
            updatereftb.set_active(True)
        
    def addreference_action(self,*args):
        addrefentry=self.builder.get_object("addrefentry")
        addrefb=self.builder.get_object("addrefb")
        updatereftb=self.builder.get_object("updatereftb")
        reflist=self.builder.get_object("reflist")
        refview=self.builder.get_object("refview")
        
        if addrefentry.is_visible()==False:
            updatereftb.hide()
            updatereftb.set_sensitive(False)
            addrefentry.set_text("")
            addrefentry.show()
            return
        
        _ref=addrefentry.get_text().strip(" ").rstrip(" ")
        if _ref=="":
            updatereftb.show()
            addrefentry.hide()
            return
        
        if _ref.find(":")==-1:
            logger().debug("invalid input")
            return
        _type,_ref=_ref.split(":",1)
        
        
        hview=self.builder.get_object("hashview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        ref_hash=_selh[0][_selh[1]][0]
        
        
        #tparam=self.header_client.copy()
        #tparam["certhash"]=ref_hash
        
        if not _type in implementedrefs:
            logger().debug("invalid type")
            return
        
        #if _type=="shash":
        #    ressname=self.do_requestdo("ask", _ref, self.header_client)
        #    if ressname[0]==False or ressname[1][0] is None:
        #        logger().error("invalid name")
        #        return
        
        res=self.do_requestdo("addreference", ref_hash, _ref, _type, self.header_client)
        if res[0]==True:
            addrefentry.hide()
            it=reflist.prepend((_ref,_type))
            refview.get_selection().select_iter(it)
            if _type in ["url", "name"] and self.curlocal[0] == "server":
                self.update_serverlist(self.curlocal[1])
            updatereftb.set_sensitive(True)
            updatereftb.show()
            updatereftb.set_active(False)
            
        else:
            logger().error(res[1])
            
    def updatereference_action(self,*args):
        updatereftb=self.builder.get_object("updatereftb")
        addrefb=self.builder.get_object("addrefb")
        addrefentry=self.builder.get_object("addrefentry")
        
        if updatereftb.get_active() == True:
            addrefb.hide()
            refview=self.builder.get_object("refview")
            _selr=refview.get_selection().get_selected()
            if _selr[1] is None:
                return
            addrefentry.show()
            addrefentry.set_text("{}:{}".format(_selr[0][_selr[1]][1],_selr[0][_selr[1]][0]))
        else:
            self.addrefentry_confirm()

    def delreference(self,*args):
        rview=self.builder.get_object("refview")
        dia=self.builder.get_object("delrefdia")
        showref=self.builder.get_object("showreference")
        showreftype=self.builder.get_object("showreferencetype")
        _selr=rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref,_type=_selr[0][_selr[1]]
        showref.set_text(_ref)
        showreftype.set_text(_type)
        dia.show()
    
    def delreference_confirm(self,*args):
        hview=self.builder.get_object("hashview")
        rview=self.builder.get_object("refview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        _selr=rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref = _selr[0][_selr[1]][0]
        
        res = self.do_requestdo("delreference", _hash, _ref, self.header_client)
        if res[0]==True:
            if _selr[0][_selr[1]][1] in ["url", "name"]:
                self.update_storage()
            self.delrefdia.hide()
            self.update_refs()
    
    def renameentity(self, *args):
        oldnameo = self.builder.get_object("oldname")
        newnameentryo = self.builder.get_object("newnameentry")
        self.close_managehashdia()
        
        localview=self.builder.get_object("localview")
        _sel=localview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name = _sel[0][_sel[1]][0]
        parentit = _sel[0].iter_parent(_sel[1])
        if parentit is None:
            return
        oldnameo.set_text(_name)
        newnameentryo.set_text("")
        self.renameentitydia.show()
        
        
    def renameentity_confirm(self, *args):
        oldname = self.builder.get_object("oldname").get_text()
        newnameentryo = self.builder.get_object("newnameentry")
        
        if newnameentryo.get_text()=="":
            return
        
        ret=self.do_requestdo("renameentity", oldname, newnameentryo.get_text(),self.header_client)
        if ret[0]==True:
            self.close_renameentitydia()
            self.update_storage()
        else:
            logger().info(ret[1])
    ### close
    
        
    def close_clientdia(self,*args):
        self.clientwin.hide()
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

    def close_addnodedia(self,*args):
        self.addnodedia.hide()
        return True
    
    def close_enternodedia(self,*args):
        self.enternodedia.hide()
        return True
    
    def close_renameentitydia(self,*args):
        self.renameentitydia.hide()
        return True
        
    def close(self,*args):
        global run
        run=False
        self.win.destroy()


class gtkclient_init(client.client_init):
    #links = client.client_init.links
    #serve_forever_nonblock = client.client_init.serve_forever_nonblock
    
    def __init__(self,confm,pluginpathes):
        self.config_path=confm.get("config")
        _cpath="{}{}{}".format(self.config_path,os.sep,"client")
        init_config_folder(self.config_path,"client")
        
        if check_certs(_cpath+"_cert")==False:
            logger().debug("Certificate(s) not found. Generate new...")
            generate_certs(_cpath+"_cert")
            logger().debug("Certificate generation complete")
        client.client_init.__init__(self, confm, pluginpathes)
        logger().debug("start client server")
        self.serve_forever_nonblock()
        logger().debug("start gtkclient")
        self.links["gtkclient"]=gtkclient_main(self.links)
        logger().replaceHandler(self.links["gtkclient"])

def do_gtkiteration():
    
    logger().debug("enter mainloop")
    while run==True:
        Gtk.main_iteration_do(True)
