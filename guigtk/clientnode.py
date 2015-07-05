#! /usr/bin/env python3

import os
from gi.repository import Gtk

from guigtk.guicommon import gtkclient_template
from common import sharedir,isself

class gtkclient_node(gtkclient_template):
    
    def __init__(self,links,_address,dheader,name=""):
        gtkclient_template.__init__(self, links,_address,dheader)
        if self.init2(os.path.join(sharedir, "guigtk", "clientnode.ui"))==False:
            return
        self.win=self.get_object("nodewin")
        if name is isself:
            self.win.set_title("This client")
        else:
            self.win.set_title(name)
        self.win.connect('delete-event',self.close)
        
        self.update()
    
    def update(self,*args):
        for plugin in self.links["client_server"].pluginmanager.plugins:
            if "gtk_node_iface" in plugin.__dict__:
                pass
    
    def update_actions(self,*args):
        for plugin in self.links["client_server"].pluginmanager.plugins:
            if "gui_node_actions" in plugin.__dict__:
                for action in gui_node_actions:
                    moo=action["text"]
                    #mooicon=action["icon"]
    
    def activate_action(self,*args):
        pass
        
    
