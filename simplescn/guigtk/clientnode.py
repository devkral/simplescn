#! /usr/bin/env python3

# bsd3, see LICENSE.txt

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib #, Pango
import socket
import logging

import os, locale

from simplescn.guigtk import set_parent_template, activate_shielded, toggle_shielded, open_hashes
#, open_hashes
from simplescn import sharedir, isself, check_name, security_states, scnparse_url, logcheck



class _gtkclient_node(Gtk.Builder,set_parent_template):
    isregistered = False
    sfilter = None
    page_names = None
    messagebuf = None
    links = None
    resdict = None
    info = None
    newaddress = None
    info_had_run = False
    def __init__(self, links, obdict):
        self.page_names = {}
        self.links = links
        self.resdict = obdict
        set_parent_template.__init__(self)
        Gtk.Builder.__init__(self)
        self.set_application(self.links["gtkclient"].app)
        self.add_from_file(os.path.join(sharedir, "guigtk", "clientnode.ui"))

    def init(self, page="info"):
        print("\""+self.get_address()+"\"")
        if self.resdict.get("forcehash") in open_hashes:
            if self.get_address() is not None:
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddresse").set_text(self.get_address())
            else:
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddresse").set_text("")

        self.win = self.get_object("nodewin")
        
        self.win.connect('delete-event', self.close)
        self.clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        
        self.init_connects()
        self.init_nodebook(page)
        return True
    
    def visible_func (self,_model,_iter,_data):
        _entry = self.get_object("servernodeentry")
        _showbr = self.get_object("showbroken").get_active()
        _val = _entry.get_text()
        if _model[_iter] is None:
            return False
        if _showbr == False and _model[_iter][1] != "valid":
            return False
        if _val in _model[_iter][2] or _val in _model[_iter][3]:
            return True
        else:
            return False

    def update_info(self, *args):
        _address = self.get_address()
        print(_address)
        if _address is not None:
            infoob = self.do_requestdo("info", address=_address)
            if infoob[0] == False:
                if self.resdict.get("forcehash") is None:
                    logging.error("no hash found")
                    return
                travret = self.do_requestdo("getreferences", hash=self.resdict.get("forcehash"), filter="surl")
                if travret[0] == False:
                    logging.error("fetching references failed")
                    return
                for _tsaddr, _type in travret[1]["items"]:
                    try:
                        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        soc.connect(scnparse_url(_tsaddr))
                        soc.close()
                        self.resdict["traverseserveraddr"] = _tsaddr
                        infoob = self.do_requestdo("info", address=_address)
                        break
                    except Exception:
                        pass
                infoob = self.do_requestdo("info", address=_address)
                if infoob[0] == False:
                    return
            self.info = infoob
            
            if "forcehash" not in self.resdict:
                self.resdict["forcehash"] = self.info[3]
            
        else:
            infoob = self.do_requestdo("getlocal", hash=self.resdict.get("forcehash"))
            if infoob[0] == False:
                return
            print(infoob)
            name = (infoob[1]["name"], infoob[1]["security"])
            self.info = (True, {"type": infoob[1]["type"], "message": "", "name": name[0]}, name, self.resdict.get("forcehash"))
        self.update_info_slate()
    
    def update_info_slate(self, *args):
        if self.info_had_run == False:
            sombie = self.get_object("securitycombo")
            secwhat = self.get_object("secwhat")
            securtypes = security_states.copy()
            if self.info[2] is isself:
                self.get_object("securityshow").set_label("self/destruct keys")
                self.get_object("destroykeysb").show()
                securtypes.remove("valid") #not valid
                secwhat.set_text("Destroy broken/old key with reason:")
            elif isinstance(self.info[2], tuple):
                self.get_object("securityshow").set_label(self.info[2][1])
                self.get_object("confirmsecb").show()
                sombie.append_text(self.info[2][1])
                securtypes.remove(self.info[2][1])
                secwhat.set_text("Set key state:")
            else:
                self.get_object("securityshow").hide()
        
            for entry in securtypes:
                sombie.append_text(entry)
            sombie.set_active(0)
        
        
            
        addresslist = self.get_object("addresslist")
        addresslist.clear()
        for elem in self.get_address_list():
            addresslist.append((elem,))
        if self.get_object("chooseaddresse").get_text() != "":
            self.get_object("chooseaddress").set_active_id(self.get_object("chooseaddresse").get_text())
        
        
        self.get_object("hashexpandl").set_text(self.info[3])
        self.get_object("typeshowl").set_text(self.info[1]["type"])
        if self.get_address() is not None:
            self.get_object("messagebuffer").set_text(self.info[1]["message"])
        self.get_object("rnamee").set_text(self.info[1]["name"])
        #if self.get_address() is not None:
        #    address = scnparse_url(self.get_address())
        #    self.get_object("addressshowl").set_text(str(address[0]))
        #    self.get_object("portshowl").set_text(str(address[1]))
        #else:
        #    self.get_object("addressshowl").set_text("None")
        #    self.get_object("portshowl").set_text(str("?"))
        
        if self.info[2] is isself:
            self.get_object("messageview").set_editable(True)
            self.get_object("updatemessageb").show()
            self.get_object("changemsgpermanent").show()
            self.get_object("updatenameg").show()
            self.get_object("rnamee").set_editable(True)
            self.get_object("rnamee").set_has_frame(True)
        self.info_had_run = True
    
    def update_server(self,*args):
        namestore=self.get_object("servernodelist")
        registerb=self.get_object("registerbutton")
        self.isregistered = False
        
        namestore.clear()
        if self.get_address() is None:
            return
        _names=self.do_requestdo("listnames",server=self.get_address())
        if _names[0]==False:
            logging.error(_names[1])
            return
        
        for name, _hash, _security, _localname in _names[1]["items"]:
            if _localname is None:
                namestore.append(("remote", _security, name, _hash, name))
            elif _localname is isself:
                self.isregistered = True
                namestore.append(("This Client", _security, name, _hash, name))
            else:
                namestore.append(("local","{} ({})".format(name, _localname, ), _security, _hash, name))
        if self.isregistered == False:
            registerb.set_label("Register")
        else:
            registerb.set_label("Update Address")
    
    def create_server_slate(self):
        #self.add_objects_from_file(_file, ["servermaingrid"])
        if self.get_address() is not None:
            self.get_object("registerbutton").show()
        sgrid = self.get_object("servermaingrid")
        self.sfilter = self.get_object("snodefilter")
        self.sfilter.set_visible_func(self.visible_func)
        view = self.get_object("servernodeview")
        col0renderer = Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("Type", col0renderer, text=0)
        view.append_column(col0)
        col1renderer=Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("State", col1renderer, text=1)
        view.append_column(col1)
        col2renderer=Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Name", col2renderer, text=2)
        view.append_column(col2)
        col3renderer=Gtk.CellRendererText()
        col3 = Gtk.TreeViewColumn("Hash", col3renderer, text=3)
        view.append_column(col3)
        Gdk.threads_add_idle(GLib.PRIORITY_LOW, self.update_server)
        return sgrid
    
    
    def update_services(self,*args):
        servicel = self.get_object("servicelist")
        if self.get_address() is None:
            return
        ret = self.do_requestdo("listservices", address=self.get_address())
        servicel.clear()
        if logcheck(ret,logging.INFO) == False:
            return
        for elem in ret[1]["items"]:
            servicel.append((elem[0],elem[1]))
        
    
    def create_service_slate(self):
        sgrid=self.get_object("servicemaingrid")
        
        serviceview = self.get_object("nodeserviceview")
        servicecol = Gtk.TreeViewColumn("Service", Gtk.CellRendererText(), text=0)
        serviceview.append_column(servicecol)
        servicecol2 = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=1)
        serviceview.append_column(servicecol2)
        Gdk.threads_add_idle(GLib.PRIORITY_LOW, self.update_services)
        return sgrid
        
    #def init_traverse(self):
    #    
    
    def init_nodebook(self, page):
        self.update_info()
        if self.info is None:
            return
        counter = 0
        noteb = self.get_object("nodebook")
        self.page_names["info"] = counter
        counter += 1
        
        
        veristate = self.get_object("veristate")
        if self.info[2] == isself:
            self.win.set_title("This client")
            veristate.set_text("This client")
            self.get_object("servicecreategrid").show()
        elif self.info[2] is None:
            self.win.set_title("Unknown Node: {}".format(self.info[3][:20]+"..."))
            veristate.set_text("Unknown Node: {}".format(self.info[3][:20]+"..."))
            self.get_object("servicegetgrid").show()
        else:
            self.win.set_title("Node: {}".format(self.info[2][0]))
            veristate.set_text("Node: {} ({})".format(self.info[2][0], self.info[2][1]))
            self.get_object("servicegetgrid").show()
        
        #self.update_info_slate()
        #noteb.set_tab_detachable(_tmp, False) #info
        
        
        category = self.info[1]["type"]
        self.init_actions(category)
        
        
        
        if category == "server":
            cat = "gui_server_iface"
            if self.get_address() is not None:
                _tmp = self.create_server_slate()
                self.page_names["server"] = counter
                counter += 1
                _tmplabel = Gtk.Label("Serverlist")
        elif category == "client":
            cat = "gui_node_iface"
            if self.get_address() is not None:
                _tmp = self.create_service_slate()
                self.page_names["services"] = counter
                counter += 1
                _tmplabel = Gtk.Label("Servicelist")
        else:
            logging.warning("Category not exist")
            noteb.show_all()
            self.connect_signals(self)
            return
        
        if self.get_address() is not None:
            noteb.append_page(_tmp, _tmplabel)
            noteb.set_tab_detachable(_tmp, False)
        self.connect_signals(self)
        for pname, plugin in sorted(self.links["client_server"].pluginmanager.plugins.items(), key=lambda x: x[0]):
            if hasattr(plugin, cat) == True:
                try:
                    if cat == "gui_server_iface":
                        _tmp = getattr(plugin, cat)("gtk", self.info[2], self.info[3], self.get_address, self.win)
                    else:
                        _tmp = getattr(plugin, cat)("gtk", self.info[2], self.info[3], self.get_address, self.get_traverseaddr, self.win)
                    if _tmp is not None:
                        if getattr(plugin, "lname"): #  and getattr(plugin, "lname") is dict:
                            llocale = locale.getlocale()[0]
                            lname = plugin.lname.get(llocale)
                            if lname is None:
                                lname = plugin.lname.get(llocale.split("_",1)[0])
                            if lname is None:
                                lname = plugin.lname.get("*", pname)
                        else:
                            lname = pname
                        noteb.append_page(_tmp, Gtk.Label(lname, tooltip_text="{} ({})".format(lname, pname)))
                        noteb.set_tab_detachable(_tmp, False)
                        self.page_names[pname] = counter
                        counter += 1
                except Exception as e:
                    logging.error(e)
        
        noteb.show_all()
        # don't connect signals, should be done by plugins itself
        #self.connect_signals(self)
        if isinstance(page, int):
            noteb.set_current_page(page)
        else:
            noteb.set_current_page(self.page_names.get(page,0))
        
    def init_actions(self, category):
        menu = self.get_object("actions")
        if category == "server":
            cat = "gui_server_actions"
        elif category == "client":
            cat = "gui_node_actions"
        else:
            logging.warning("Category not exist")
            cat = "gui_node_actions"
        actionmenub = self.get_object("nodeactionbutton")
        issensitiveset = False
        actionmenub.set_sensitive(False)
        for plugin in self.links["client_server"].pluginmanager.plugins.values():
            if hasattr(plugin, cat):
                try:
                    for action in getattr(plugin, cat):
                        if "action" not in action or "text" not in action or "gtk" not in action.get("interfaces", []):
                            continue
                        item = Gtk.MenuItem()
                        itemb = Gtk.Grid(orientation=Gtk.Orientation.HORIZONTAL, column_spacing=3)
                        item.add(itemb)
                        
                        
                        if action.get("state") is not None:
                            tb = Gtk.CheckButton(active=action.get("state"))
                            itemb.attach_next_to(tb, None, Gtk.PositionType.RIGHT, 1, 1)
                            
                        if "icon" in action:
                            itemb.attach_next_to(Gtk.Image.new_from_file(action["icon"]), None, Gtk.PositionType.RIGHT, 1, 1)
                        

                        itemb.attach_next_to(Gtk.Label(action["text"]), None, Gtk.PositionType.RIGHT, 1, 1)
                        if "description" in action:
                            itemb.set_tooltip_text(action["description"])
                        itemb.show_all()
                        item.show()
                        if action.get("state") is not None:
                            item.connect('activate', toggle_shielded(action["action"], tb, self.get_address, self.win, self.resdict))
                        else:
                            item.connect('activate', activate_shielded(action["action"], self.get_address, self.win, self.resdict))
                        menu.append(item)
                        if issensitiveset == False:
                            actionmenub.set_sensitive(True)
                            issensitiveset = True
                except Exception as e:
                    logging.error(e)
                    

# update message
    def update_message(self, *args):
        messagebuf = self.get_object("messagebuffer")
        if messagebuf.get_modified() == False:
            return
            
        start, end = messagebuf.get_bounds()
        _text = messagebuf.get_text(start, end, True)
        
        #ret = 
        self.do_requestdo("changemsg", message=_text, permanent=self.get_object("changemsgpermanent").get_active())
        #if ret[0] == False:
        #    
    
    def update_name(self, *args):
        _name = self.get_object("rnamee").get_text()
        if check_name(_name) == False:
            logging.info("Invalid name: {}".format(_name))
            return
        #ret = 
        self.do_requestdo("changename", name=_name, permanent=self.get_object("changenamepermanent").get_active())
        #if ret[0] == False:
        #    
        
# service extras
    def copy_service(self,*args):
        view = self.get_object("nodeserviceview")
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service="{address}:{port}".format(address=self.get_address().rsplit(":",1)[0],port=_sel[0][_sel[1]][1])
        self.clip.set_text(service,-1)
        self.close()
# own services extras
    
        
    def add_service(self,*args):
        localservicelist = self.get_object("servicelist")
        servicee = self.get_object("newservicenameentry")
        porte = self.get_object("newserviceportentry")
        service = servicee.get_text().strip(" ").rstrip(" ")
        port = porte.get_text().strip(" ").rstrip(" ")
        if service=="":
            logging.debug("service invalid")
            return
        if port == "" or port.isdecimal() == False:
            logging.debug("port invalid")
            return
        ret = self.do_requestdo("registerservice", name=service, port=port)
        if ret[0] == False:
            logging.debug(ret[1])
            return
        servicee.set_text("")
        porte.set_text("")
        
        localservicelist.append((service, int(port)))
        
    def sel_service(self,*args):
        view=self.get_object("nodeserviceview")
        but=self.get_object("deleteserviceb")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            but.hide()
        else:
            but.show()

    def del_service(self,*args):
        view=self.get_object("nodeserviceview")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service=_sel[0][_sel[1]][0]
        if service=="":
            return
        ret=self.do_requestdo("delservice", name=service)
        if ret[0]==False:
            return
        self.update_services()



        
        
# server extras
    def action_snode(self, justselect):
        view = self.get_object("servernodeview")
        
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            return
        
        _name, _hash = _sel[0][_sel[1]][2:4] #_entry.get_text().split("/",1)
        
        _check = self.do_requestdo("check", server=self.get_address(), name=_name, hash=_hash)
        if logcheck(_check, logging.DEBUG) == False:
            return
        
        _node = self.do_requestdo("get", server=self.get_address(), name=_name, hash=_hash)
        if logcheck(_node, logging.ERROR) == False:
            return
        
        self.links["gtkclient"].set_curnode("{}-{}".format(_node[1]["address"], _node[1]["port"]), _name, _hash, self.get_address())
        if justselect == False:
            _res = self.resdict.copy()
            _res["forcehash"] = _hash
            gtkclient_node(self.links, "{}-{}".format(_node[1]["address"],_node[1]["port"]), _name, **_res)
        self.close()
        
    def get_snode(self,*args):
        self.action_snode(False)
        
    def select_snode(self,*args):
        self.action_snode(True)
        
    def snode_activate(self,*args):
        self.get_snode(True)
        
    
#    def snode_row_select(self,*args):
#        view = self.get_object("servernodeview")
#        _entry =self.get_object("servernodeentry")
#        _sel = view.get_selection().get_selected()
#        if _sel[1] is None:
#            return
#        _entry.set_text(_sel[0][_sel[1]][3])
        
    
    def snode_filter(self,*args):
        self.sfilter.refilter()
    
    def register_ownnode(self,*args):
        registerb = self.get_object("registerbutton")
        namestore = self.get_object("servernodelist")
        res = self.do_requestdo("register", server=self.get_address())
        if res[0] == False:
            logging.error(res[1])
            return
        if self.isregistered==False:
            res_show = self.do_requestdo("show")
            if res_show == False:
                logging.error(res[1])
                return
            self.isregistered=True
            namestore.prepend(("This Client", "valid", res_show[1]["name"], res_show[1]["hash"], res_show[1]["name"]))
            registerb.set_label("Update Address")


# security
    def open_security(self, *args):
        self.get_object("setsecuritywin").show()
        
    def confirm_security(self, *args):
        self.get_object("setsecuritywin").hide()
        sectype = self.get_object("securityentry").get_text()
        ret = self.do_requestdo("changesecurity", hash=self.resdict.get("forcehash"), security=sectype)
        if ret[0] == True:
            self.get_object("securityshow").set_label(sectype)
        else:
            self.get_object("securitycombo").set_active(0)
    
    def confirm_keydestruction(self, *args):
        sectype = self.get_object("securityentry").get_text()
        
        ret = self.do_requestdo("invalidatecert", reason=sectype)
        self.get_object("setsecuritywin").hide()
        if ret[0] == True:
            #self.get_object("securityshow").set_label(sectype)
            self.resdict["forcehash"] = self.links["client"].cert_hash
    def cancel_security(self, *args):
        self.get_object("setsecuritywin").hide()
## gtk template

    def do_requestdo(self,action, **obdict):
        od = self.resdict.copy()
        od.update(obdict)
        return self.links["gtkclient"].do_requestdo(action, **od)
    
    def get_address_list(self):
        ret = []
        for elem in open_hashes[self.resdict.get("forcehash")][1]:
            ret.append(elem)
        return sorted(ret)
    
    def get_traverseaddr(self):
        return self.resdict.get("traverseserveraddr")

    def get_address(self):
        if len(open_hashes[self.resdict.get("forcehash")][1])==0:
            return None
        return self.get_object("chooseaddresse").get_text()
    
    def close(self,*args):
        self.win.hide()
        self.links["gtkclient"].app.remove_window(self.win)
        del open_hashes[self.resdict.get("forcehash")]
        self.win.destroy()
        del self


def gtkclient_node(links, _address, page="info", **obdict):
    if obdict.get("forcehash") is None and _address is None:
        return None
    elif obdict.get("forcehash") is None:
        ret = links["gtkclient"].do_requestdo("info", address=_address)
        if ret[0] == False:
            return None
        self.info = ret
        obdict["forcehash"] = ret[3]
    
    ret = None
    if obdict.get("forcehash") not in open_hashes:
        ret = _gtkclient_node(links, obdict)
        open_hashes[obdict.get("forcehash")] = [ret, set()]
        if _address is not None:
            open_hashes[obdict.get("forcehash")][1].add(_address)
            open_hashes[obdict.get("forcehash")][0].get_object("chooseaddresse").set_text(_address)
        ret.init(page="info")
    else:
        if _address is not None:
            open_hashes[obdict.get("forcehash")][1].add(_address)
            open_hashes[obdict.get("forcehash")][0].get_object("chooseaddresse").set_text(_address)
            open_hashes[obdict.get("forcehash")][0].update_info()
            open_hashes[obdict.get("forcehash")][0].get_object("chooseaddress").set_active_id(_address)
        open_hashes[obdict.get("forcehash")][0].win.present()
        open_hashes[obdict.get("forcehash")][0].win.set_accept_focus(True)
        ret = open_hashes[obdict.get("forcehash")][0]
    return ret
