#! /usr/bin/env python3

import os

from gi.repository import Gtk
from guigtk.guicommon import gtkclient_template
from common import sharedir,isself

class gtkclient_server(gtkclient_template):
    isregistered=False
    
    def visible_func (self,_model,_iter,_data):
        _entry=self.get_object("servernodeentry")
        _val=_entry.get_text()
        if _val==_model[_iter][3][:len(_val)]:
            return True
        else:
            return False
    
    def __init__(self,links,_address,dheader,name=""):
        gtkclient_template.__init__(self, links,_address,dheader)
        if self.init2(os.path.join(sharedir, "guigtk", "clientserver.ui"))==False:
            return
        
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
        
        if name is isself:
            self.win.set_title("This client")
        else:
            self.win.set_title(name)
        
        self.filter.set_visible_func(self.visible_func)
        
        self.connect_signals(self)
        self.win.connect('delete-event',self.close)
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
                namestore.append(("self",elem[0],elem[1],"{}/{}".format(elem[0],elem[1])))
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
        
        self.links["gtkclient"].set_curnode("{}:{}".format(*_node[1]), _name, _hash, self.address)
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
        registerb=self.get_object("registerbutton")
        namestore=self.get_object("servernodelist")
        res=self.do_requestdo("register",self.address)
        if res[0]==False:
            logging.error(res[1])
        if self.isregistered==False:
            self.isregistered=True
            namestore.prepend((self.links["client_server"].name,self.links["client"].cert_hash,"This client","{}/{}".format(self.links["client_server"].name,self.links["client"].cert_hash)))
            registerb.set_label("Update Address")

