#! /usr/bin/env python3

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

run = True
open_addresses={}


def activate_shielded(action, url, **obdict):
    def shielded(widget):
        action("gtk", url, {"forcehash": obdict.get("forcehash")})
    return shielded

class gtkclient_template(Gtk.Builder):
    links = None
    win = None
    resdict = None
    address = None
    #autoclose=0 #closes window after a timeperiod
    
    def __init__(self,links,_address, **obdict):
        self.links = links
        self.resdict = obdict
        self.address = _address
        
    def init2(self, _file):
        classname = type(self).__name__
        if self.address not in open_addresses:
            open_addresses[self.address] = [classname, self]
        elif open_addresses[self.address][0] is classname:
            open_addresses[self.address][1].win.present()
            open_addresses[self.address][1].win.set_accept_focus(True)
            return False
        else:
            open_addresses[self.address][1].close()
            open_addresses[self.address]=[classname, self]
        Gtk.Builder.__init__(self)
        
        self.set_application(self.links["gtkclient"])
        self.add_from_file(_file)
        return True
        
    def do_requestdo(self,action, **obdict):
        od = self.resdict.copy()
        od.update(obdict)
        return self.links["gtkclient"].do_requestdo(action, **od)
    
    def close(self,*args):
        self.win.hide()
        self.links["gtkclient"].remove_window(self.win)
        del open_addresses[self.address]
        self.win.destroy()
        del self


