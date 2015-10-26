#! /usr/bin/env python3

import os, locale
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango

from guigtk.guicommon import gtkclient_template, activate_shielded, toggle_shielded
from common import sharedir,isself, logger, check_name, security_states, scnparse_url



class gtkclient_node(gtkclient_template):
    isregistered = False
    sfilter = None
    page_names = None
    messagebuf = None
    def __init__(self, links, _address, page="info", **obdict):
        self.page_names = {}
        gtkclient_template.__init__(self, links, _address, **obdict)
        if self.init2(os.path.join(sharedir, "guigtk", "clientnode.ui"))==False:
            return
        self.win = self.get_object("nodewin")
        self.win.connect('delete-event', self.close)
        
        self.init_connects()
        self.init_nodebook(page)
    
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
    
    def create_info_slate(self, _infoob=None):
        
        #self.col.foreach(clearme)
        if _infoob is None:
            _infoob = self.do_requestdo("info", address=self.address)
        if _infoob[0] == False:
            return None
        sombie = self.get_object("securitycombo")
        secwhat = self.get_object("secwhat")
        securtypes = security_states.copy()
        if _infoob[2] is isself:
            self.get_object("securityshow").set_label("self/destruct keys")
            self.get_object("destroykeysb").show()
            securtypes.remove("valid") #not valid
            secwhat.set_text("Destroy broken/old key with reason:")
        elif isinstance(_infoob[2], tuple):
            self.get_object("securityshow").set_label(_infoob[2][1])
            self.get_object("confirmsecb").show()
            sombie.append_text(_infoob[2][1])
            securtypes.remove(_infoob[2][1])
            secwhat.set_text("Set key state:")
        else:
            self.get_object("securityshow").hide()
        
        for entry in securtypes:
            sombie.append_text(entry)
        sombie.set_active(0)
        
        maininfo = self.get_object("infomaingrid")
        self.get_object("hashexpandl").set_text(_infoob[3])
        self.get_object("typeshowl").set_text(_infoob[1]["type"])
        self.get_object("messagebuffer").set_text(_infoob[1]["message"])
        self.get_object("rnamee").set_text(_infoob[1]["name"])
        address = scnparse_url(self.address)
        
        self.get_object("portshowl").set_text(str(address[1]))
        if _infoob[2] is isself:
            self.get_object("messageview").set_editable(True)
            self.get_object("updatemessageb").show()
            self.get_object("changemsgpermanent").show()
            self.get_object("updatenameg").show()
            self.get_object("rnamee").set_editable(True)
            self.get_object("rnamee").set_has_frame(True)
            
        return maininfo
    
    def update_server(self,*args):
        namestore=self.get_object("servernodelist")
        registerb=self.get_object("registerbutton")
        self.isregistered = False
        
        namestore.clear()
        _names=self.do_requestdo("listnames",server=self.address)
        if _names[0]==False:
            logger().error(_names[1])
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
        self.update_server()
        return sgrid
    
    
    def update_services(self,*args):
        servicel = self.get_object("servicelist")
        ret = self.do_requestdo("listservices", address=self.address)
        servicel.clear()
        if ret[0] == False:
            logging.info(ret[1])
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
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.win.connect('delete-event',self.close)
        self.update_services()
        return sgrid
        
    #def init_traverse(self):
    #    
    
    def init_nodebook(self, page):
        counter = 0
        noteb = self.get_object("nodebook")
        infoob = self.do_requestdo("info", address=self.address)
        if infoob[0] == False:
            return
        name = infoob[2]
        self.resdict["forecehash"] = infoob[3]
        if infoob[1].get(infoob[1]["type"], "") != "server":
            self.resdict["traverseserveraddr"] = self.links["gtkclient"].builder.get_object("servercomboentry").get_text().strip(" ").rstrip(" ")
            travret = self.do_requestdo("getreferences", hash=infoob[3], filter="surl")
            if travret[0] and self.resdict["traverseserveraddr"] not in travret[1]["items"]:
                for _tsaddr, _type in travret[1]["items"]:
                    try:
                        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        soc.connect(scn_parseurl(_tsaddr))
                        soc.close()
                        break
                    except Exception:
                        pass
        
        veristate = self.get_object("veristate")
        if name == isself:
            self.win.set_title("This client")
            veristate.set_text("This client")
            self.get_object("servicecreategrid").show()
        elif name is None:
            self.win.set_title("Unknown Node: {}".format(infoob[3][:20]+"..."))
            veristate.set_text("Unknown Node: {}".format(infoob[3][:20]+"..."))
            self.get_object("servicegetgrid").show()
        else:
            self.win.set_title("Node: {}".format(name[0]))
            veristate.set_text("Node: {} ({})".format(name[0], name[1]))
            self.get_object("servicegetgrid").show()
            
        _tmp = self.create_info_slate(infoob)
        noteb.append_page(_tmp, Gtk.Label("Info"))
        noteb.set_tab_detachable(_tmp, False)
        self.page_names["info"] = counter
        counter += 1
        
        
        category = infoob[1]["type"]
        self.init_actions(category)
        
        
        
        if category == "server":
            cat = "gui_server_iface"
            _tmp = self.create_server_slate()
            self.page_names["server"] = counter
            counter += 1
            _tmplabel = Gtk.Label("Serverlist")
        elif category == "client":
            cat = "gui_node_iface"
            _tmp = self.create_service_slate()
            self.page_names["services"] = counter
            counter += 1
            _tmplabel = Gtk.Label("Servicelist")
        else:
            logger().warning("Category not exist")
            noteb.show_all()
            self.connect_signals(self)
            return
        
        noteb.append_page(_tmp, _tmplabel)
        noteb.set_tab_detachable(_tmp, False)
        self.connect_signals(self)
        for pname, plugin in sorted(self.links["client_server"].pluginmanager.plugins.items(), key=lambda x: x[0]):
            if hasattr(plugin, cat) == True:
                try:
                    _tmp = getattr(plugin, cat)("gtk", infoob[2], infoob[3], self.address)
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
                    logger().error(e)
        
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
            logger().warning("Category not exist")
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
                            item.connect('activate', toggle_shielded(action["action"], tb, self.address, **self.resdict))
                        else:
                            item.connect('activate', activate_shielded(action["action"], self.address, **self.resdict))
                        menu.append(item)
                        if issensitiveset == False:
                            actionmenub.set_sensitive(True)
                            issensitiveset = True
                except Exception as e:
                    logger().error(e)
                    

# update message
    def update_message(self, *args):
        messagebuf = self.get_object("messagebuffer")
        if messagebuf.get_modified() == False:
            return
            
        start, end = messagebuf.get_bounds()
        _text = messagebuf.get_text(start, end, True)
        
        ret = self.do_requestdo("changemsg", message=_text, permanent=self.get_object("changemsgpermanent").get_active())
        #if ret[0] == False:
        #    
    
    def update_name(self, *args):
        _name = self.get_object("rnamee").get_text()
        if check_name(_name) == False:
            logger().info("Invalid name: {}".format(_name))
            return
        ret = self.do_requestdo("changename", name=_name, permanent=self.get_object("changenamepermanent").get_active())
        #if ret[0] == False:
        #    
        
# service extras
    def copy_service(self,*args):
        view = self.get_object("nodeserviceview")
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service="{address}:{port}".format(address=self.address.rsplit(":",1)[0],port=_sel[0][_sel[1]][1])
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
            logger().debug("service invalid")
            return
        if port == "" or port.isdecimal() == False:
            logger().debug("port invalid")
            return
        ret = self.do_requestdo("registerservice", name=service, port=port)
        if ret[0] == False:
            logger().debug(ret[1])
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
        
        _check = self.do_requestdo("check", server=self.address, name=_name, hash=_hash)
        if _check[0] == False:
            
            return
        
        _node = self.do_requestdo("get", server=self.address, name=_name, hash=_hash)
        if _node[0] == False:
            logger().error(_node[1])
            return
        
        self.links["gtkclient"].set_curnode("{}-{}".format(_node[1]["address"], _node[1]["port"]), _name, _hash, self.address)
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
        res = self.do_requestdo("register", server=self.address)
        if res[0] == False:
            logger().error(res[1])
            return
        if self.isregistered==False:
            res_show = self.do_requestdo("show")
            if res_show == False:
                logger().error(res[1])
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
