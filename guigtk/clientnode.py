#! /usr/bin/env python3

from gi.repository import Gtk

from guigtk.guicommon import gtkclient_template
from common import sharedir,isself

class gtkclient_node(gtkclient_template):
    
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,sharedir+"guigtk/clientnode.ui",links,_address,dparam)
        self.win=self.get_object("nodewin")
        self.win.set_title(name)
        
        self.update()
    
    def update(self,*ars):
        pass
    
    def update_actions(self):
        pass
        
    
    def activate_action(self,*args):
        pass
    
