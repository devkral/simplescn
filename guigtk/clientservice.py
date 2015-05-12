#! /usr/bin/env python3

from gi.repository import Gtk
from guigtk.guicommon import gtkclient_template

from common import sharedir,isself

class gtkclient_remoteservice(gtkclient_template):
    name=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"guigtk/clientservice.ui",links,_address,dparam)
        self.name=name
        #self.get_object("col1").set_orientation(Gtk.Orientation.VERTICAL)
        self.win=self.get_object("servicewin")
        self.win.set_visible(True)
        self.win.set_title(name)
        self.update()
        
    def update(self):
        pass
        
