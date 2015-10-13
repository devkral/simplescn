#! /usr/bin/env python3

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk
from guigtk import clientdialogs

run = True
open_addresses={}


def activate_shielded(action, url, **obdict):
    def shielded(widget):
        action("gtk", url, {"forcehash": obdict.get("forcehash")})
    return shielded


def toggle_shielded(action, togglewidget, url, **obdict):
    togglewidget._toggle_state_scn = togglewidget.get_active()
    def shielded(widget):
        if togglewidget._toggle_state_scn == True:
            action("gtk", url, False, {"forcehash": obdict.get("forcehash")})
            togglewidget.set_active(False)
            togglewidget._toggle_state_scn = False
        else:
            action("gtk", url, True, {"forcehash": obdict.get("forcehash")})
            togglewidget.set_active(True)
            togglewidget._toggle_state_scn = True
    return shielded

class set_parent_template(object):
    win = None
    added = False
    
    def init_connects(self):
        self.win.connect("window-state-event", self.select_byfocus)
    
    def select_byfocus(self, widget, event):
        if event.new_window_state&Gdk.WindowState.FOCUSED != 0:
            self.addstack()
        else:
            self.delstack()
        
    
    def addstack(self, *args):
        if self.added == False:
            clientdialogs.parentlist.append(self.win)
            self.added = True
    
    def delstack(self, *args):
        if self.added == True:
            clientdialogs.parentlist.remove(self.win)
            self.added = False
        



class gtkclient_template(Gtk.Builder, set_parent_template):
    links = None
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


