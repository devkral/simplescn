#! /usr/bin/env python3


import os
from common import sharedir,isself, scnparse_url

from gi.repository import Gtk
from guicommon import gtkclient_template
from clientservice import gtkclient_remoteservice

def clearme(widget):
    widget.destroy()

class gtkclient_info(gtkclient_template):
    name=None
    col=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self, links, _address,dparam)
        if self.init2(os.path.join(sharedir, "guigtk", "clientinfo.ui"))==False:
            return
        #self.get_object("col1").set_orientation(Gtk.Orientation.VERTICAL)
        self.col=self.get_object("col")
        self.win=self.get_object("infowin")
                
        if name is isself:
            self.win.set_title("This client")
        else:
            self.win.set_title(name)
        self.name=name
        
        
        self.connect_signals(self)
        self.win.connect('delete-event',self.close)
        self.update()
        
    
    def update(self,*args):
        messagebuf=self.get_object("messagebuf")
        
        self.col.foreach(clearme)
        if self.name is isself:
            self.col_entry("Name (this client) ","")
        else:
            self.col_entry("Name: ",self.name)
        self.col_entry("Address: ",self.address)
        if self.dparam["certhash"] is not None:
            self.col_entry("Hash: ",self.dparam["certhash"])
        else:
            self.col_entry("Hash: ", "<empty>")
        
        
    
        _info=self.do_requestdo("info",self.address,parse=2)
        if _info[0]==True:
            messagebuf.set_text(_info[1][2],-1)
    
    def col_entry(self,key,val):
        grid=Gtk.Grid()
        grid.set_visible(True)
        grid.set_column_spacing(3)
        label1=Gtk.Label(key)
        label1.set_selectable(True)
        label1.set_visible(True)
        label2=Gtk.Label(val)
        label2.set_selectable(True)
        label2.set_visible(True)
        grid.attach(label1,0,0,1,1)
        grid.attach(label2,1,0,1,1)
        self.col.pack_end(grid,False,False,0)
        
    def openservices(self,*args):
        gtkclient_remoteservice(self.links, self.address, self.dparam, self.name)

