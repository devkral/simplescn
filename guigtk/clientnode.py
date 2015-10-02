#! /usr/bin/env python3

import os
from gi.repository import Gtk

from guigtk.guicommon import gtkclient_template, activate_shielded
from common import sharedir,isself, logger



class gtkclient_node(gtkclient_template):
    def __init__(self, links, _address, name="",  **obdict):
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
        
        self.update()
        self.update_actions()
    
    def update(self,*args):
        noteb = self.get_object("nodebook")
        t = Gtk.Label("Hello {}".format(self.address))
        noteb.append_page(t, Gtk.Label("Welcome"))
        noteb.set_tab_detachable(t, False)
        
        for name, plugin in sorted(self.links["client_server"].pluginmanager.plugins.items(), key=lambda x: x[0]):
            if hasattr(plugin, "gtk_node_iface") == True:
                noteb.append_page(plugin.gtk_node_iface, Gtk.Label(name))
                noteb.set_tab_detachable(plugin.gtk_node_iface, False)
        
        noteb.show_all()
    
    def update_actions(self,*args):
        menu = self.get_object("actions")
        for plugin in self.links["client_server"].pluginmanager.plugins.values():
            if "gui_node_actions" in plugin.__dict__:
                try:
                    for action in plugin.gui_node_actions:
                        if "action" not in action or "text" not in action:
                            continue
                        item = Gtk.MenuItem()
                        itemb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                        item.add(itemb)
                        itemb.pack_end(Gtk.Label(action["text"]), True, True,0)
                        if "icon" in action:
                            itemb.pack_end(Gtk.Image.new_from_file(action["icon"]), True, True,0)
                        itemb.show_all()
                        item.show()
                        item.connect('activate',activate_shielded(action["action"],self.address,**self.resdict))
                        menu.append(item)
                except Exception as e:
                    logger().error(e)
    
