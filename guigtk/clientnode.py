#! /usr/bin/env python3

import os
from gi.repository import Gtk, Gdk, Pango

from guigtk.guicommon import gtkclient_template, activate_shielded
from common import sharedir,isself, logger



class gtkclient_node(gtkclient_template):
    def __init__(self, links, _address, name="", switchfrominfo=False, **obdict):
        gtkclient_template.__init__(self, links, _address, **obdict)
        if self.init2(os.path.join(sharedir, "guigtk", "clientnode.ui"))==False:
            return
        self.win = self.get_object("nodewin")
        veristate = self.get_object("veristate")
        if name == isself:
            self.win.set_title("This client")
            veristate.set_text("This client")
        else:
            self.win.set_title("Node: {}".format(name))
            veristate.set_text("Node: {}".format(name))
        self.win.connect('delete-event', self.close)
        self.init_nodebook(switchfrominfo)
    
    def create_info_slate(self, _infoob=None):
        #self.col.foreach(clearme)
        if _infoob is None:
            _infoob = self.do_requestdo("info", address=self.address)
        if _infoob[0] == False:
            return
        if _infoob[2] == isself:
            self.get_object("servicecreategrid").show()
        else:
            self.get_object("servicegetgrid").show()
            
        g = Gtk.Grid()
        g.attach(Gtk.Label("Hash: "), 0, 0, 1, 1)
        _thash = Gtk.Label(_infoob[3])
        width_chars = 40
        _thash.set_line_wrap_mode(Pango.WrapMode.CHAR)
        _thash.set_max_width_chars(width_chars)
        _thash.set_width_chars(width_chars)
        _thash.set_line_wrap(True)
        _thash.set_lines(-1)
        g.attach(_thash, 1, 0, 1, 1)
        g.attach(Gtk.Label("Type: "), 0, 1, 1, 1)
        g.attach(Gtk.Label(_infoob[1]["type"]), 1, 1, 1, 1)
        t = Gtk.TextBuffer()
        g.attach(Gtk.TextView(buffer=t), 2, 1, 1, 1)
        t.set_text(_infoob[1]["message"],-1)
        
        return g
    
    def update_server(self,*args):
        namestore=self.get_object("servernodelist")
        registerb=self.get_object("registerbutton")
        self.isregistered=False
        namestore.clear()
        _names=self.do_requestdo("listnames",server=self.address)
        if _names[0]==False:
            logger().error(_names[1])
            return
        for name, _hash, _localname in _names[1]["items"]:
            if _localname is None:
                namestore.append(("remote",name,_hash,"{}/{}".format(name,_hash)))
            elif _localname is isself:
                self.isregistered=True
                namestore.append(("self",name,_hash,"{}/{}".format(name,_hash)))
            else:
                namestore.append(("local","{} ({})".format(name, _localname),_hash,"{}/{}".format(name,_hash)))
        if self.isregistered==False:
            registerb.set_label("Register")
        else:
            registerb.set_label("Update Address")
    
    def create_server_slate(self):
        #self.add_objects_from_file(_file, ["servermaingrid"])
        sgrid = self.get_object("servermaingrid")
        self.get_object("registerbutton").show()
        self.sfilter = self.get_object("snodefilter")
        view = self.get_object("servernodeview")
        col0renderer = Gtk.CellRendererText()
        col0 = Gtk.TreeViewColumn("state", col0renderer, text=0)
        view.append_column(col0)
        col1renderer=Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("Name", col1renderer, text=1)
        view.append_column(col1)
        col2renderer=Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Hash", col2renderer, text=2)
        view.append_column(col2)
        self.update_server()
        return sgrid
    
    
    def update_services(self,*args):
        servicel=self.get_object("servicelist")
        ret=self.do_requestdo("listservices", address=self.address)
        if ret[0]==False:
            logging.info(ret[1])
            return
        servicel.clear()
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
        self.connect_signals(self)
        self.win.connect('delete-event',self.close)
        self.update_services()
        return sgrid
        
    
    def init_nodebook(self, switchfrominfo):
        noteb = self.get_object("nodebook")
        infoob = self.do_requestdo("info", address=self.address)
        if infoob[0] == False:
            return
        
        _tmp = self.create_info_slate(infoob)
        noteb.append_page(_tmp, Gtk.Label("Info"))
        noteb.set_tab_detachable(_tmp, False)
        
        category = infoob[1]["type"]
        self.init_actions(category)
        
        
        
        if category == "server":
            cat = "gui_server_iface"
            _tmp = self.create_server_slate()
            _tmplabel = Gtk.Label("Serverlist")
        elif category == "client":
            cat = "gui_node_iface"
            _tmp = self.create_service_slate()
            _tmplabel = Gtk.Label("Servicelist")
        else:
            logger().warning("Category not exist")
            noteb.show_all()
            return
        
        noteb.append_page(_tmp, _tmplabel)
        noteb.set_tab_detachable(_tmp, False)
        
        for name, plugin in sorted(self.links["client_server"].pluginmanager.plugins.items(), key=lambda x: x[0]):
            if hasattr(plugin, cat) == True:
                _tmp = plugin.gtk_node_iface
                noteb.append_page(_tmp, Gtk.Label(name))
                noteb.set_tab_detachable(_tmp, False)
        
        noteb.show_all()
        if switchfrominfo:
            noteb.set_current_page(1)
        else:
            noteb.set_current_page(0)
    
    def init_actions(self, category):
        menu = self.get_object("actions")
        if category == "server":
            cat = "gui_server_actions"
        elif category == "client":
            cat = "gui_node_actions"
        else:
            logger().warning("Category not exist")
            cat = "gui_node_actions"
        for plugin in self.links["client_server"].pluginmanager.plugins.values():
            if hasattr(plugin, cat):
                try:
                    for action in plugin.gui_node_actions:
                        if "action" not in action or "text" not in action:
                            continue
                        item = Gtk.MenuItem()
                        itemb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                        item.add(itemb)
                        itemb.pack_end(Gtk.Label(action["text"]), True, True, 0)
                        if "icon" in action:
                            itemb.pack_end(Gtk.Image.new_from_file(action["icon"]), True, True, 0)
                        itemb.show_all()
                        item.show()
                        item.connect('activate', activate_shielded(action["action"], self.address, **self.resdict))
                        menu.append(item)
                except Exception as e:
                    logger().error(e)
    
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
        print("\""+port+"\"")
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
    def action_snode(self, action):
        _entry = self.get_object("servernodeentry")
        val = _entry.get_text()
        if val == "" or val.find("/") == -1:
            return
        _name,_hash=_entry.get_text().split("/",1)
        _node = self.do_requestdo("get", server=self.address, name=_name, hash=_hash)
        if _node[0]==False:
            logger().error(_node[1])
            return
        self.links["gtkclient"].set_curnode("{}:{}".format(_node[1]["address"], _node[1]["port"]), _name, _hash, self.address)
        #TODO: enum
        if action == 0:
            pass
        elif action == 1:
            gtkclient_node(self.links, "{}:{}".format(_node[1]["address"],_node[1]["port"]), _name, **self.resdict)
        self.close()
        
    def get_snode(self,*args):
        self.action_snode(1)
        
    def select_snode(self,*args):
        self.action_snode(0)
        
    def snode_activate(self,*args):
        view=self.get_object("servernodeview")
        _entry=self.get_object("servernodeentry")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _entry.set_text(_sel[0][_sel[1]][0])
        self.snode_get()
        
        
    
    def snode_row_select(self,*args):
        view=self.get_object("servernodeview")
        _entry=self.get_object("servernodeentry")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        _entry.set_text(_sel[0][_sel[1]][3])
        
    
    def snode_filter(self,*args):
        self.sfilter.refilter()
    
    def register_ownnode(self,*args):
        registerb = self.get_object("registerbutton")
        namestore = self.get_object("servernodelist")
        res = self.do_requestdo("register",server=self.address)
        if res[0] == False:
            logger().error(res[1])
            return
        if self.isregistered==False:
            res_show=self.do_requestdo("show")
            if res_show==False:
                logger().error(res[1])
                return
            self.isregistered=True
            namestore.prepend(("self", res_show[1]["name"], res_show[1]["hash"], "{}/{}".format(res_show[1]["name"], res_show[1]["hash"])))
            registerb.set_label("Update Address")




