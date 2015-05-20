#! /usr/bin/env python3

import os
from gi.repository import Gtk

from guicommon import gtkclient_template
from common import sharedir,isself

class gtkclient_node(gtkclient_template):
    
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self,os.path.join(sharedir, "guigtk", "clientnode.ui"),links,_address,dparam)
        self.win=self.get_object("nodewin")
        self.win.set_title(name)
        
        self.update()
    
    def update(self,*ars):
        pass
    
    def update_actions(self):
        pass
        
    
    def activate_action(self,*args):
        pass
    
