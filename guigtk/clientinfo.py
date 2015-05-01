#! /usr/bin/env python3

from common import sharedir,isself

from gi.repository import Gtk
from guigtk.guicommon import gtkclient_template

class gtkclient_info(gtkclient_template):
    name=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"guigtk/clientinfo.ui",links,_address,dparam)
        self.name=name
        #self.get_object("col1").set_orientation(Gtk.Orientation.VERTICAL)
        col1=self.get_object("col1")
        col2=self.get_object("col2")
        self.win=self.get_object("infowin")
        self.win.set_visible(True)
        self.win.set_title(name)
        self.update()
        
    def update(self):
        self.get_object("addressl").set_text(self.address)
        self.get_object("infonamel").set_text(self.name)
        if self.dparam["certhash"] is not None:
            self.get_object("hashl").set_text(self.dparam["certhash"])
        else:
            self.get_object("hashl").set_text("<None>")
        
        
    
        #_info=self.do_requestdo("info",self.address,parse=2)
        #if _info[0]==True:
        #    pass
    
    def col1_entry(self,name,value):
        pass
        
        
        
    def col2_entry(self,name,value):
        pass

