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
        self.localview=self.builder.get_object("localview")
        self.localstore=self.builder.get_object("localstore")
        self.recentview=self.builder.get_object("recentview")
        self.recentstore=self.builder.get_object("recentstore")
        self.statusbar=self.builder.get_object("mainstatusbar")
        
        self.debugwin=self.builder.get_object("debugwin")
        self.cmdwin=self.builder.get_object("cmdwin")
        self.clientwin=self.builder.get_object("clientdia")
        self.mswin=self.builder.get_object("manageserviceswin")
        self.addnamedia=self.builder.get_object("addnamedia")
        self.delnamedia=self.builder.get_object("delnamedia")
        self.addnodedia=self.builder.get_object("addnodedia")
        self.delnodedia=self.builder.get_object("delnodedia")
        
        
        self.debug_wintoggle=self.builder.get_object("debugme")
        self.cmd_wintoggle=self.builder.get_object("cmdme")
        self.client_wintoggle=self.builder.get_object("useremoteclient")
        
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
        
        serviceview=self.builder.get_object("localserviceview")
        servicecolrenderer=Gtk.CellRendererText()
        servicecol = Gtk.TreeViewColumn("Service", servicecolrenderer, text=0)
        serviceview.append_column(servicecol)
        servicecol2renderer=Gtk.CellRendererText()
        servicecol2 = Gtk.TreeViewColumn("Port", servicecol2renderer, text=1)
        serviceview.append_column(servicecol2)
        
        
        self.debugwin.connect('delete-event',self.close_debug)
        self.cmdwin.connect('delete-event',self.close_cmd)
        self.clientwin.connect('delete-event',self.close_client)
        self.mswin.connect('delete-event',self.close_manages)
        self.addnamedia.connect('delete-event',self.close_addname)
        self.delnamedia.connect('delete-event',self.close_delname)
        self.addnodedia.connect('delete-event',self.close_addnode)
        self.delnodedia.connect('delete-event',self.close_delnode)
        
        
        #self.clientwin.connect('delete-event',self.close_client)
        
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
    def addnodehash_intern(self,_node,_hash):
        #_
        #_hash=
        
        
        self.addnodehashdia.show()
        self.addnodehashdia.grab_focus()
        #else:
        #    self.debugwin.hide()
    
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
        services=self.do_requestdo("listservices")
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
        
    def select_local(self,*args):
        pass
        
    def client_help(self, args):
        pass
    
    
    
    
    def cmd_do(self,*args):
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
                    print("Unverified")
                elif resp[2] is isself:
                    print("Is own client")
                else:
                    print("Verified as: "+resp[2])
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
        
    def close_client(self,*args):
        self.clientwin.hide()
        return True
    
    def close_manages(self,*args):
        self.mswin.hide()
        return True
    
    def close_addname(self,*args):
        self.addnamedia.hide()
        return True
        
    def close_delname(self,*args):
        self.delnamedia.hide()
        return True
        
    def close_addnode(self,*args):
        self.addnodedia.hide()
        return True
        
    def close_delnode(self,*args):
        self.delnodedia.hide()
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
