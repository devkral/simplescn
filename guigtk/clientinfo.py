#! /usr/bin/env python3

from common import sharedir,isself

from gi.repository import Gtk
from guicommon import gtkclient_template

class gtkclient_info(gtkclient_template):
    name=None
    col=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"guigtk/clientinfo.ui",links,_address,dparam)
        self.name=name
        #self.get_object("col1").set_orientation(Gtk.Orientation.VERTICAL)
        self.col=self.get_object("col")
        self.win=self.get_object("infowin")
        self.win.set_visible(True)
        self.win.set_title(name)
        self.connect_signals(self)
        self.update()
        
    def update(self):
        self.col.clear()
        self.col_entry("Name: ",self.name)
        self.col_entry("Address: ",self.address)
        if self.dparam["certhash"] is not None:
            self.col_entry("Hash: ",self.dparam["certhash"])
        else:
            self.col_entry("Hash: ", "<empty>")
        
        
    
        #_info=self.do_requestdo("info",self.address,parse=2)
        #if _info[0]==True:
        #    pass
    
    def col_entry(self,tup1,tup2=None):
        grid=Gtk.Grid()
        label1=Gtk.Label(tup1[0])
        label1.set_selectable(True)
        label2=Gtk.Label(tup1[0])
        label2.set_selectable(True)
        grid.add(label1)
        grid.add(label2)
        
        if tup2 is not None:
            label3=Gtk.Label(tup2[0])
            label3.set_selectable(True)
            label4=Gtk.Label(tup2[0])
            label4.set_selectable(True)
            grid.add(label3)
            grid.add(label4)
        self.col.add(grid)
        self.col.show
        

