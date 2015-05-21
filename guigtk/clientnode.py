#! /usr/bin/env python3

import os
from gi.repository import Gtk

from guicommon import gtkclient_template
from common import sharedir,isself

class gtkclient_node(gtkclient_template):
    
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self, links,_address,dparam)
        if self.init2(os.path.join(sharedir, "guigtk", "clientnode.ui"))==False:
            return
        self.win=self.get_object("nodewin")
        self.win.set_title(name)
        self.win.connect('delete-event',self.close)
        
        self.update()
    
    def update(self,*args):
        pass
    
    def update_actions(self):
        pass
        
    
    def activate_action(self,*args):
        pass
        
    
