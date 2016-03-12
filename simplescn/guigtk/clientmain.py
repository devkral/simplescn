#! /usr/bin/env python3
# bsd3, see LICENSE.txt

import os
import sys
import logging
import time
import threading
import traceback

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib

import simplescn
from simplescn import client, logcheck

from simplescn.guigtk.clientmain_sub import cmd_stuff, debug_stuff, configuration_stuff, help_stuff
from simplescn.guigtk.clientmain_managehash import hashmanagement
from simplescn.guigtk.clientdialogs import gtkclient_pw, gtkclient_notify, parentlist
from simplescn.guigtk.clientnode import gtkclient_node
from simplescn.guigtk import set_parent_template, implementedrefs

from simplescn import default_sslcont, sharedir, isself, check_hash, scnparse_url, AddressEmptyFail, generate_error
#debug_mode
messageid = 0

class gtkclient_main(logging.Handler, configuration_stuff, cmd_stuff, debug_stuff, help_stuff, hashmanagement, set_parent_template):
    links = None
    curnode = None
    curlocal = None
    app = None
    win = None

    builder = None
    clip = None
    backlog = []
    statusbar = None

    localstore = None
    serverlist_dic = []

    recentstore = None
    recentcount = 0
    remote_client = None
    #use_remote_client=False

    clientwin = None

    remoteclient_url = ""
    remoteclient_hash = ""
    use_localclient = True

    cert_hash = None
    #start_url_hash=(None,None)
    _old_serverurl = ""

    def __init__(self, _links):
        self.links = _links
        logging.Handler.__init__(self)
        #self.setFormatter(logging.Formatter('%(levelname)s::%(filename)s:%(lineno)d::%(funcName)s::%(message)s'))
        self.app = Gtk.Application()
        self.sslcont = default_sslcont()
        self.builder = Gtk.Builder()
        self.builder.set_application(self.app)
        self.builder.add_from_file(os.path.join(sharedir, "guigtk", "clientmain.ui"))
        self.builder.add_from_file(os.path.join(sharedir, "guigtk", "clientmain_sub.ui"))
        #self.app.add_window(self.builder.get_object("mainwin"))
        self.builder.connect_signals(self)
        self.clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.win = self.builder.get_object("mainwin")
        self.localstore = self.builder.get_object("localstore")
        self.recentstore = self.builder.get_object("recentstore")
        self.statusbar = self.builder.get_object("mainstatusbar")
        self.hashstatusbar = self.builder.get_object("hashstatusbar")
        recentview = self.builder.get_object("recentview")
        localview = self.builder.get_object("localview")

        help_stuff.__init__(self)
        debug_stuff.__init__(self)
        configuration_stuff.__init__(self)
        cmd_stuff.__init__(self)
        hashmanagement.__init__(self)

        listnodetypes = self.builder.get_object("listnodetypes")
        listnodetypes.append(("server", "Server"))
        listnodetypes.append(("client", "Friend"))
        listnodetypes.append(("unknown", "Unknown"))

        self.clientwin = self.builder.get_object("clientdia")
        self.addentitydia = self.builder.get_object("addentitydia")
        self.delentitydia = self.builder.get_object("delentitydia")
        self.delrefdia = self.builder.get_object("delrefdia")
        self.addnodedia = self.builder.get_object("addnodedia")
        self.delnodedia = self.builder.get_object("delnodedia")
        self.enternodedia = self.builder.get_object("enternodedia")
        self.renameentitydia = self.builder.get_object("renameentitydia")


        addnodecombo = self.builder.get_object("addnodecombo")
        addnodecomborenderer = Gtk.CellRendererText()
        addnodecombo.pack_start(addnodecomborenderer, True)
        addnodecombo.add_attribute(addnodecomborenderer, "text", 0)
        addnodetypecombo = self.builder.get_object("addnodetypecombo")
        addnodetypecomborenderer = Gtk.CellRendererText()
        addnodetypecombo.pack_start(addnodetypecomborenderer, True)
        addnodetypecombo.add_attribute(addnodetypecomborenderer, "text", 1)

        col0 = Gtk.TreeViewColumn("Nodes", Gtk.CellRendererText(), text=0)
        localview.append_column(col0)

        recentcol = Gtk.TreeViewColumn("Recent", Gtk.CellRendererText(), text=0)
        recentview.append_column(recentcol)
        recentcol2 = Gtk.TreeViewColumn("Url", Gtk.CellRendererText(), text=1)
        recentview.append_column(recentcol2)

        self.localstore = self.builder.get_object("localstore")

        self.clientwin.connect('delete-event', self.close_clientdia)
        self.addentitydia.connect('delete-event', self.close_addentitydia)
        self.delentitydia.connect('delete-event', self.close_delentitydia)
        self.delrefdia.connect('delete-event', self.close_delrefdia)
        self.addnodedia.connect('delete-event', self.close_addnodedia)
        self.delnodedia.connect('delete-event', self.close_delnodedia)
        self.enternodedia.connect('delete-event', self.close_enternodedia)
        self.renameentitydia.connect('delete-event', self.close_renameentitydia)
        self.win.connect('delete-event', self.close)
        self.init_connects()
        self.update_storage()

    def update_storage(self):
        """ func: update local storage """
        _storage = self.do_requestdo("listnodenametypes")
        if logcheck(_storage) == False:
            return
        self.localstore.clear()
        self.serverit = self.localstore.insert_with_values(None, -1, [0], ["Server"])
        self.server_dic = []
        self.friendit = self.localstore.insert_with_values(None, -1, [0], ["Friend"])
        self.friend_dic = []
        self.unknownit = self.localstore.insert_with_values(None, -1, [0], ["Unknown"])
        self.unknown_dic = []
        self.emptyit = self.localstore.insert_with_values(None, -1, [0], ["Empty"])
        self.empty_dic = []
        
        #serverlist=self.builder.get_object("serverlist")
        #serverlist.clear()
        for elem in _storage[1]["items"]:
            if elem[0] is None:
                logging.critical("None element as name")
                return
            if elem[1] is None:
                self.empty_dic += [elem[0]]
            elif elem[1] == "server":
                self.update_serverlist(elem[0])
                self.server_dic += [elem[0]]
                self.localstore.insert_with_values(self.serverit, -1, [0], [elem[0]])
            elif elem[1] == "client":
                self.friend_dic += [elem[0]]
                self.localstore.insert_with_values(self.friendit, -1, [0], [elem[0]])
            else:
                self.unknown_dic += [elem[0]]
                self.localstore.insert_with_values(self.unknownit, -1, [0], [elem[0]])
                
        for elem in self.server_dic+self.friend_dic+self.unknown_dic:
            if elem in self.empty_dic:
                self.empty_dic.remove(elem)

        for elem in self.empty_dic:
            self.localstore.insert_with_values(self.emptyit, -1, [0], [elem])

        localnames = self.builder.get_object("localnames")
        localnames.clear()
        localnames.append(("",))
        _names = self.do_requestdo("listnodenames")
        if logcheck(_names) == False:
            return
        for elem in _names[1]["items"]:
            localnames.append((elem,))

    def update_serverlist_refid(self, _refid):
        serverlist = self.builder.get_object("serverlist")
        _serverrefs = self.do_requestdo("getreferences", certreferenceid=_refid)
        if logcheck(_serverrefs) == False:
            return
        for elem in _serverrefs[1]["items"]:
            if elem[0] not in self.serverlist_dic:
                if elem[1] == "name":
                    serverlist.append((elem[0], True))
                    self.serverlist_dic.append(elem[0])
                elif elem[1] == "url":
                    serverlist.append((elem[0], False))
                    self.serverlist_dic.append(elem[0])
                    
    def update_serverlist(self, _localname):
        _serverhashes = self.do_requestdo("listhashes", name=_localname)
        if logcheck(_serverhashes):
            for _hash in _serverhashes[1]["items"]:
                if _hash[0] != "default":
                    self.update_serverlist_refid(_hash[4])

    def do_requestdo(self, action, forcelocal=False, forceremote=False, **obdict):
        """ func: execute requests """
        # use_localclient is True if client was set successfully
        # can force remote or local
        if (self.use_localclient == True or forcelocal == True) and forceremote == False:
            resp = self.links["client"].access_main(action, **obdict)
        else:
            clienturl = self.builder.get_object("clienturl").get_text().strip().rstrip()
            clienthash = self.builder.get_object("clienthash").get_text().strip().rstrip()
            if clienthash == "":
                clienthash = None
            obdict["pwcall_method"] = self.links["client"].pw_auth
            try:
                resp = self.links["client"].do_request(clienturl, "/client/{}".format(action), body=obdict, forcehash=clienthash, sendclientcert=True, forceport=True)
            except Exception as exc:
                #if debug_mode:
                #    logging.error(exc)
                return False, generate_error(exc), isself, self.links["client"].cert_hash
        return resp

    def pushint(self):
        """ func: delete messsage after 5 seconds """
        time.sleep(5)
        Gdk.threads_add_idle(GLib.PRIORITY_LOW, self._pushint)

    def _pushint(self):
        """ func: intern pushint """
        self.statusbar.pop(messageid)
        self.hashstatusbar.pop(messageid)
        return False

    def pushmanage(self, *args):
        threading.Thread(target=self.pushint, daemon=True).start()

    ### logging handling ###
    def emit(self, record):
        """ func: handle logging records """
        Gdk.threads_add_idle(GLib.PRIORITY_HIGH, self._emit, record)

    blcounter = 0
    def _emit(self, record):
        """ func: intern emit """
        backlogret = self.do_requestdo("get_config", forcelocal=True, key="backlog")
        if not backlogret[0]:
            print(backlogret[1], file=sys.stderr)
            bllength = 1
        else:
            bllength = max(0, backlogret[1].get("value"))
        if self.blcounter == bllength and self.blcounter > 0:
            self.backlogdebug.remove(self.backlogdebug.get_iter_first())
        elif self.blcounter > bllength:
            while self.blcounter > bllength:
                self.backlogdebug.remove(self.backlogdebug.get_iter_first())
                self.blcounter -= 1
        else:
            self.blcounter += 1

        if record.exc_info:
            backtr = "".join(traceback.format_tb(record.exc_info)).replace("\\n", "") #record.stack_info
        elif record.stack_info:
            backtr = record.stack_info #"".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", "")
        else:
            backtr = "n.a." #record.getMessage()
        shortmsg = record.getMessage()
        #"".join(traceback.format_tb(sys.exc_info()[2])).replace("\\n", "")
        if self.blcounter > 0:
            self.backlogdebug.append((shortmsg, backtr, record.levelno))
        self.statusbar.push(messageid, shortmsg)
        self.hashstatusbar.push(messageid, shortmsg)
        self.pushmanage()
        return False

    def _verifyserver(self, serverurl):
        """ func: update verifystateserver widget
            return: ask information
            serverurl: server url """ 
        _veri = self.builder.get_object("veristateserver")
        if serverurl == "":
            _veri.set_text("")
            return None

        _hash = self.do_requestdo("ask", address=serverurl)
        if _hash[0] == False:
            _veri.set_text("")
            return None

        if _hash[1].get("localname") is None:
            _veri.set_text("Unknown server")
        elif _hash[1].get("localname") == isself:
            _veri.set_text("This client")
        else:
            _veri.set_text("Verified as:\n{}\n ({})".format(_hash[1].get("localname"), _hash[1].get("security")))
        return _hash[1]
        
    def veristate_server(self, *args):
        """ use servercomboentry widget, call _verifyserver """
        serverurl = self.builder.get_object("servercomboentry").get_text()
        servlist = self.builder.get_object("serverlist")
        if self._verifyserver(serverurl) is not None:
            if serverurl not in self.serverlist_dic:
                servlist.append((serverurl, False))
                self.serverlist_dic.append(serverurl)
    
    def set_curnode(self, _clientaddress, _name, _hash, _serveraddress=None):
        """ set current node """
        if self.curnode is not None and self.curnode[0] != isself:
            self.recentstore.prepend(self.curnode)
            if self.recentcount < 20:
                self.recentcount += 1
            else:
                self.recentstore.remove(self.recentstore.iter_n_children(20))

        cnode = self.builder.get_object("curnode")
        cnodeorigin = self.builder.get_object("nodeorigin")
        opennodeb = self.builder.get_object("opennodeb")
        _ask = self.do_requestdo("ask", address=_clientaddress)
        if not _ask[0]:
            cnodeorigin.set_text("")
            cnode.set_text("invalid")
            opennodeb.set_sensitive(False)
            self.curnode = None
        elif _ask[1].get("localname") is None:
            cnodeorigin.set_text("remote:")
            cnode.set_text(_name)
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode = (None, _clientaddress, _name, _hash, _serveraddress)
        elif _ask[1].get("localname") == isself:
            cnodeorigin.set_text("")
            cnode.set_text("This client")
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode = (isself, _clientaddress, _name, _hash, _serveraddress)
        else:
            cnodeorigin.set_text("verified:")
            cnode.set_text(_ask[1].get("localname"))
            opennodeb.show()
            opennodeb.set_sensitive(True)
            self.curnode = (_ask[1].get("localname"), _clientaddress, _name, _hash, _serveraddress)

    def open_server(self, *args):
        """ func: use servercomboentry to open node """
        serverurl = self.builder.get_object("servercomboentry").get_text()
        askinfo = self._verifyserver(serverurl)
        if askinfo is None:
            return
        #if askinfo.get("localname") is None:
        #    name = serverurl[:20]
        #elif askinfo.get("localname") == isself:
        #    name = "Own server"
        #else:
        #    #name = askinfo.get("localname")
        gtkclient_node(self.links, "{}-{}".format(*scnparse_url(serverurl)), forcehash=askinfo.get("hash"), page="server")

    ### node actions ###
    def addnodehash_intern(self, _name, _hash, _type="unknown", refstoadd=()):
        addnodecombo = self.builder.get_object("addnodecombo")
        addnodehashentry = self.builder.get_object("addnodehashentry")
        addnodetypeentry = self.builder.get_object("addnodetypecombo")

        addnodecombo.set_active_id(_name)
        addnodehashentry.set_text(_hash)
        addnodetypeentry.set_active_id(_type)
        # save refs which should be added in classvariable
        self._intern_refstoadd = refstoadd
        self.addnodedia.show()
        self.addnodedia.grab_focus()

    def addnodehash(self, *args):
        localview = self.builder.get_object("localview")
        _sel = localview.get_selection().get_selected()
        if _sel[1] is None:
            _name = ""
        else:
            _name = _sel[0][_sel[1]][0]
        if self.curnode is None:
            self.addnodehash_intern(_name, "", "client")
        else:
            if self.curnode[4] is None:
                self.addnodehash_intern(_name, self.curnode[3], "client", refstoadd=(("name", self.curnode[2])))
            else:
                self.addnodehash_intern(_name, self.curnode[3], "client", refstoadd=(("surl", self.curnode[4]), ("name", self.curnode[2])))


    def addnodehash_confirm(self, *args):
        addnodecombo = self.builder.get_object("addnodecombo")
        addnodehashentry = self.builder.get_object("addnodehashentry")
        addnodetypecombo = self.builder.get_object("addnodetypecombo")

        hashlist = self.builder.get_object("hashlist")
        hashview = self.builder.get_object("hashview")

        _name = addnodecombo.get_active_id()
        _hash = addnodehashentry.get_text().strip(" ").rstrip(" ")
        _type = addnodetypecombo.get_active_id()
        
        if _name is None:
            return
        if _type == "":
            _type = "unknown"
        if not check_hash(_hash):
            logging.debug("invalid hash")
            return
        res = self.do_requestdo("addhash", name=_name, hash=_hash, type=_type)
        if logcheck(res):
            self.update_storage()
            if self.curlocal is not None and _type == self.curlocal[0]:
                it = hashlist.prepend((_hash,))
                hashview.get_selection().select_iter(it)
            #self.update_hashes()
            # apply refs (saved in classvariable) from addnodehash
            for elem in self._intern_refstoadd:
                self.do_requestdo("addreference", hash=_hash, reference=elem[1], reftype=elem[0])
            self.close_addnodedia()
        else:
            logging.error(str(res[1]))

    def delnodehash(self, *args):
        view = self.builder.get_object("recentview")
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _hash = _sel[0][_sel[1]][3]
        ret = self.do_request("delhash", hash=_hash)
        if ret[0]:
            logging.info("Could not delete hash")

    def enternode(self, *args):
        self.builder.get_object("enternodeurl").set_text("")
        self.builder.get_object("enternodehash").set_text("")
        self.enternodedia.show()
        self.enternodedia.grab_focus()

    def enternode_confirm(self, *args):
        _address = self.builder.get_object("enternodeurl").get_text().strip(" ").rstrip(" ")
        _hasho = self.builder.get_object("enternodehash")
        _hash = _hasho.get_text().strip(" ").rstrip(" ")
        if _hash == "":
            ret = self.do_requestdo("gethash", address=_address)
            if not logcheck(ret, logging.INFO):
                return
            _hasho.set_text(ret[1]["hash"])
            return
        if not check_hash(_hash):
            logging.info("hash wrong")
            return
        if _address == "":
            logging.info("address wrong")
            return
        ret = self.do_requestdo("info", hash=_hash)
        if not logcheck(ret, logging.ERROR):
            return
        self.set_curnode(_address, ret[1]["name"], _hash, None)
        self.close_enternodedia()
        self.opennode()
    
    def opennode(self, *args):
        """ func: open current node """
        if self.curnode is not None:
            gtkclient_node(self.links, self.curnode[1], forcehash=self.curnode[3], page="services", traverseserveraddr=self.curnode[4])
    
    def opennode_self(self, *args):
        """ func: open own node """
        ret = self.do_requestdo("show")
        if ret[0]:
            gtkclient_node(self.links, "localhost-{}".format(ret[1]["port"]), forcehash=ret[1]["hash"], page="services")

    def activate_recent(self, *args):
        """ func: set current node from recent list """
        view = self.builder.get_object("recentstore")
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _address = _sel[0][_sel[1]][1]
        _name = _sel[0][_sel[1]][2]
        _hash = _sel[0][_sel[1]][3]
        self.set_curnode(_address, _name, _hash, None)


    ### server actions ###

    def addserverhash(self, *args):
        """ func: add server hash """
        serverurl = self.builder.get_object("servercomboentry").get_text().strip(" ").rstrip(" ")
        serverurl = "{}-{}".format(*scnparse_url(serverurl))
        localview = self.builder.get_object("localview")
        temp = self._verifyserver(serverurl)
        if temp is None:
            logging.debug("Something failed")
            return
        _hash = temp.get("hash")

        _sel = localview.get_selection().get_selected()
        if _sel[1] is None:
            _name = ""
        else:
            _name = _sel[0][_sel[1]][0]

        self.managehashdia.hide()
        #serverurl.find("")
        if temp.get("localname") is None:
            self.addnodehash_intern(_name, _hash, "server", refstoadd=(("url", serverurl),))
        else:
            res = self.do_requestdo("addreference", hash=_hash, reference=serverurl, reftype="url")
            if res[0] == False:
                logging.debug("Already exists")

    ### client actions ###

    def clientme(self,*args):
        """ func: switch between controlling remote client and own client """
        self.builder.get_object("clienturl").set_text(self.remoteclient_url)
        self.builder.get_object("clienthash").set_text(self.remoteclient_hash)
        self.builder.get_object("uselocal").set_active(self.use_localclient)
        self.clientwin.show()
        self.clientwin.grab_focus()

    def client_confirm(self,*args):
        clurl = self.builder.get_object("clienturl")
        clhash = self.builder.get_object("clienthash")
        ulocal = self.builder.get_object("uselocal")
        _hash = clhash.get_text().strip(" ").rstrip(" ")
        _url = clurl.get_text().strip().rstrip()
        if _url == "":
            self.close_clientdia()
            return
        if _hash == "":
            ret = self.do_requestdo("gethash", forcelocal=True, address=_url)
            if logcheck(ret, logging.INFO) == False:
                return
            clhash.set_text(ret[1]["hash"])
            return
        if not ulocal.get_active():
            if _url == "":
                return
            if not check_hash(_hash):
                return
        # deactivate old
        if not self.use_localclient and self.remoteclient_url != _url:
            ret = self.do_requestdo("delredirect", forceremote=True)
            if not ret[0]:
                logging.debug("delredirect failed")
            self.links["trusted_certhash"] = ""
        self.remoteclient_url = clurl.get_text()
        self.remoteclient_hash = _hash
        # get local port
        _showret = self.do_requestdo("show", forcelocal=True)
        if not _showret[0]:
            logging.error("Error: redirect not possible; servercomponent of client not active")
            self.close_clientdia()
            return
        # activate new if it is remote
        if not ulocal.get_active():
            ret = self.do_requestdo("addredirect", forceremote=True, port=_showret[1].get("port"))
            if not logcheck(ret, logging.ERROR):
                return
            self.links["trusted_certhash"] = _hash
            self.use_localclient = False
            self.close_clientdia()
        else:
            self.links["trusted_certhash"] = ""
            self.use_localclient = True
            self.close_clientdia()

    def client_localtoggle(self, *args):
        toggle = self.builder.get_object("uselocal")
        clurl = self.builder.get_object("clienturl")
        clhash = self.builder.get_object("clienthash")
        if toggle.get_active():
            clurl.set_sensitive(False)
            clhash.set_sensitive(False)
        else:
            clurl.set_sensitive(True)
            clhash.set_sensitive(True)

    ### misc actions ###

    def checkserver(self, *args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        try:
            serverurl="{}-{}".format(*scnparse_url(serverurl))
        except AddressEmptyFail:
            logging.debug("Address Empty")
            return
        if self.do_requestdo("prioty_direct",address=serverurl)[0] == False:
            logging.debug("Server address invalid")
            return
        self.update_storage()

    ### etc ###

    def addentity(self, *args):
        self.builder.get_object("addentityentry").set_text("")
        self.addentitydia.show()

    def addentity_confirm(self, *args):
        addentity = self.builder.get_object("addentityentry")
        localnames = self.builder.get_object("localnames")
        addnodecombo = self.builder.get_object("addnodecombo")
        _entity = addentity.get_text()
        res = self.do_requestdo("addentity", name=_entity)
        if logcheck(res):
            self.addentitydia.hide()
            self.empty_dic += [_entity]
            # add to proposal list
            localit = localnames.append((_entity,))
            # select entry
            addnodecombo.set_active_iter(localit)
            self.localstore.insert_with_values(self.emptyit, -1, [0], [_entity])

    def delentity(self, *args):
        entity = self.builder.get_object("showentity")
        entity.set_text(self.curlocal[1])
        self.delentitydia.show()

    def delentity_confirm(self, *args):
        res = self.do_requestdo("delentity", name=self.curlocal[1])
        if res[0]:
            self.update_storage()
            self.delentitydia.hide()

    def delhash(self, *args):
        hview = self.builder.get_object("hashview")
        dia = self.builder.get_object("delnodedia")
        showhash = self.builder.get_object("showhash")
        referencecount = self.builder.get_object("referencecount")
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash = _selh[0][_selh[1]][0]
        showhash.set_text(_hash)
        refsl = self.do_requestdo("getreferences", hash=_hash)

        if refsl[0]:
            referencecount.set_text(str(len(refsl[1])))
        dia.show()

    def delhash_confirm(self, *args):
        hview = self.builder.get_object("hashview")
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash = _selh[0][_selh[1]][0]
        res = self.do_requestdo("delhash", hash=_hash)
        if res[0]:
            self.delnodedia.hide()
            self.update_hashes()
            self.update_storage()

    def addrefentry_confirm(self, *args):
        updatereftb = self.builder.get_object("updatereftb")
        if not updatereftb.get_sensitive():
            self.addreference_action()
        else:
            self.updatereference_way(self)

    def addreference_action(self, *args):
        addrefentry = self.builder.get_object("addrefentry")
        #addrefb=self.builder.get_object("addrefb")
        updatereftb = self.builder.get_object("updatereftb")
        reflist = self.builder.get_object("reflist")
        refview = self.builder.get_object("refview")

        if not addrefentry.is_visible():
            updatereftb.hide()
            updatereftb.set_sensitive(False)
            addrefentry.set_text("")
            addrefentry.show()
            return

        _ref = addrefentry.get_text().strip(" ").rstrip(" ")
        if _ref == "":
            updatereftb.show()
            addrefentry.hide()
            return

        if _ref.find(":") == -1:
            logging.debug("invalid input")
            return
        _type, _ref = _ref.split(":", 1)

        hview = self.builder.get_object("hashview")
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        ref_hash = _selh[0][_selh[1]][0]

        if not _type in implementedrefs:
            logging.debug("invalid type")
            return

        res = self.do_requestdo("addreference", hash=ref_hash, reference=_ref, reftype=_type)
        if res[0]:
            addrefentry.hide()
            it=reflist.prepend((_ref,_type))
            refview.get_selection().select_iter(it)
            if _type in ["url", "name"] and self.curlocal[0] == "server":
                self.update_serverlist(self.curlocal[1])

            updatereftb.set_sensitive(True)
            updatereftb.show()
            updatereftb.set_active(False)
        else:
            logging.error(res[1])

    def updatereference_way(self, *args):
        updatereftb = self.builder.get_object("updatereftb")
        # path for updating
        addrefentry = self.builder.get_object("addrefentry")
        addrefb = self.builder.get_object("addrefb")
        #reflist=self.builder.get_object("reflist")
        #refview=self.builder.get_object("refview")
        hview = self.builder.get_object("hashview")
        if self.__update_ref_run_stop:
            return

        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            logging.debug("invalid hash selection")
            updatereftb.set_active(True)
            return
        ref_hash = _selh[0][_selh[1]][0]
        _ref_entry = addrefentry.get_text().strip(" ").rstrip(" ")
        if _ref_entry == "":
            updatereftb.set_active(False)
            addrefb.show()
            addrefentry.hide()
            return

        if _ref_entry.find(":") == -1:
            logging.debug("invalid input")
            updatereftb.set_active(True)
            return
        _type, _ref=_ref_entry.split(":", 1)

        if not _type in implementedrefs:
            logging.debug("invalid type")
            updatereftb.set_active(True)
            return
        res = self.do_requestdo("updatereference", hash=ref_hash, reference=self._cache_old_ref[0], newreference=_ref, newreftype=_type)
        if res[0]:
            self.__update_ref_run_stop = True
            if _type in ["url", "name"]:
                self.update_storage()
            addrefb.show()
            addrefentry.hide()
            # update cached information
            self._cache_old_ref[1][0] = _ref
            self._cache_old_ref[1][1] = _type
            updatereftb.set_active(False)
        else:
            logging.error(res[1])
            updatereftb.set_active(True)

    def updatereference_action(self, *args):
        updatereftb = self.builder.get_object("updatereftb")
        addrefb = self.builder.get_object("addrefb")
        addrefentry = self.builder.get_object("addrefentry")

        if updatereftb.get_active():
            addrefb.hide()
            refview = self.builder.get_object("refview")
            _selr = refview.get_selection().get_selected()
            if _selr[1] is None:
                return
            self.__update_ref_run_stop = False
            self._cache_old_ref = (_selr[0][_selr[1]][0], _selr[0][_selr[1]])
            addrefentry.set_text("{}:{}".format(_selr[0][_selr[1]][1], _selr[0][_selr[1]][0]))
            addrefentry.show()
            addrefentry.grab_focus()
        else:
            self.updatereference_way()

    def delreference(self, *args):
        rview = self.builder.get_object("refview")
        dia = self.builder.get_object("delrefdia")
        showref = self.builder.get_object("showreference")
        showreftype = self.builder.get_object("showreferencetype")
        _selr = rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref, _type = _selr[0][_selr[1]]
        showref.set_text(_ref)
        showreftype.set_text(_type)
        dia.show()

    def delreference_confirm(self, *args):
        hview = self.builder.get_object("hashview")
        rview = self.builder.get_object("refview")
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash = _selh[0][_selh[1]][0]
        _selr = rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref = _selr[0][_selr[1]][0]
        
        res = self.do_requestdo("delreference", hash=_hash, reference=_ref)
        if res[0]:
            if _selr[0][_selr[1]][1] in ["url", "name"]:
                self.update_storage()
            self.delrefdia.hide()
            self.update_refs()

    def renameentity(self, *args):
        oldnameo = self.builder.get_object("oldname")
        newnameentryo = self.builder.get_object("newnameentry")
        self.close_managehashdia()
        localview = self.builder.get_object("localview")
        _sel = localview.get_selection().get_selected()
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
        if newnameentryo.get_text() == "":
            return

        ret = self.do_requestdo("renameentity", name=oldname, newname=newnameentryo.get_text())
        if ret[0]:
            self.close_renameentitydia()
            self.update_storage()
        else:
            logging.info(ret[1])

    ### close ###

    def close_clientdia(self, *args):
        self.clientwin.hide()
        return True

    def close_addentitydia(self, *args):
        self.addentitydia.hide()
        return True

    def close_delentitydia(self, *args):
        self.delentitydia.hide()
        return True

    def close_delnodedia(self, *args):
        self.delnodedia.hide()
        return True

    def close_delrefdia(self, *args):
        self.delrefdia.hide()
        return True

    def close_addnodedia(self, *args):
        self.addnodedia.hide()
        return True

    def close_enternodedia(self, *args):
        self.enternodedia.hide()
        return True

    def close_renameentitydia(self, *args):
        self.renameentitydia.hide()
        return True
        
    def close(self, *args):
        gtkclient_init.run = False
        self.win.destroy()

def open_gtk_node(_address, forcehash=None, page=0, requester=""):
    """ plugin: open a node window
        forcehash: shall a certification hash be enforced
        page: name or number of page
        requester: requesting plugin """
    gtkclient_node(gtkclient_instance.links, _address, forcehash=forcehash, page=page)
    
def open_gtk_pwcall_plugin(msg, requester):
    """ plugin: open a password dialog
        return: pw or None
        requester: requesting plugin """
    if requester != "":
        return gtkclient_pw(msg, requester)
    else:
        return None
    
def open_gtk_notify_plugin(msg, requester):
    """ plugin: open a notification dialog
        return: True or False
        requester: requesting plugin """
    if requester != "":
        return gtkclient_notify(msg, requester)
    else:
        return None

class gtkclient_init(client.client_init):
    def __init__(self, confm, pluginm):
        logging.root.setLevel(confm.get("loglevel"))
        logging.debug("start gtkclient")
        simplescn.pwcallmethodinst = gtkclient_pw
        simplescn.notifyinst = gtkclient_notify

        client.client_init.__init__(self, confm, pluginm)
        self.links["gtkclient"] = gtkclient_main(self.links)

        logging.getLogger().addHandler(self.links["gtkclient"])
        parentlist.insert(0, self.links["gtkclient"].win)
        if not confm.getb("noserver"):
            logging.debug("start client server")
            self.serve_forever_nonblock()
    def enter_gtkmainloop(self):
        logging.debug("enter mainloop")
        # needed? https://developer.gnome.org/glib/stable/glib-Deprecated-Thread-APIs.html
        # threadsubsystem seems to be initialized automatically
        #GLib.threads_init()
        #Gtk.main()
        while gtkclient_init.run:
            Gtk.main_iteration_do(True)

# for open_gtk_node and debug?
gtkclient_instance = None
def _init_method_gtkclient(confm, pluginm):
    global gtkclient_instance
    gtkclient_instance = gtkclient_init(confm, pluginm)
    if not confm.getb("noplugins"):
        pluginm.resources["access"] = gtkclient_instance.links["client"].access_safe
        pluginm.resources["plugin"] = gtkclient_instance.links["client"].use_plugin
        pluginm.resources["open_node"] = open_gtk_node
        pluginm.resources["open_pwrequest"] = open_gtk_pwcall_plugin
        pluginm.resources["open_notify"] = open_gtk_notify_plugin
        pluginm.init_plugins()
    gtkclient_instance.enter_gtkmainloop()
    sys.exit(0)
