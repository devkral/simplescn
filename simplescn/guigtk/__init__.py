#! /usr/bin/env python3

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk

from simplescn.guigtk import clientdialogs

run = True
open_hashes={}

def activate_shielded(action, urlfunc, window, obdict):
    def shielded(widget):
        action("gtk", urlfunc(), window, obdict.get("forcehash"), obdict.copy())
    return shielded


def toggle_shielded(action, togglewidget, urlfunc, window, obdict):
    togglewidget._toggle_state_scn = togglewidget.get_active()
    def shielded(widget):
        if togglewidget._toggle_state_scn == True:
            action("gtk", urlfunc(), window, obdict.get("forcehash"), False, obdict.copy())
            togglewidget.set_active(False)
            togglewidget._toggle_state_scn = False
        else:
            action("gtk", urlfunc(), window, obdict.get("forcehash"), True, obdict.copy())
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
    info = None
    newaddress = None
    #activeid = None
    
    #own init method
    def init(self, _file, links, _address, obdict):
        self.links = links
        self.resdict = obdict
        
        if self.resdict.get("forcehash") is None and _address is None:
            return False
        elif self.resdict.get("forcehash") is None:
            ret = self.do_requestdo("info", address=_address)
            if ret[0] == False:
                return False
            self.info = ret
            self.resdict["forcehash"] = ret[3]
        
        if self.resdict.get("forcehash") not in open_hashes:
            open_hashes[self.resdict.get("forcehash")] = [self, set()]
            if _address is not None:
                open_hashes[self.resdict.get("forcehash")][1].add(_address)
        else:
            if _address is not None:
                open_hashes[self.resdict.get("forcehash")][1].add(_address)
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddresse").set_text(_address)
                open_hashes[self.resdict.get("forcehash")][0].update_info()
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddress").set_active_id(_address)
            open_hashes[self.resdict.get("forcehash")][0].win.present()
            open_hashes[self.resdict.get("forcehash")][0].win.set_accept_focus(True)
            return False
        Gtk.Builder.__init__(self)
        self.set_application(self.links["gtkclient"].app)
        self.add_from_file(_file)
        if self.resdict.get("forcehash") in open_hashes:
            if _address is not None:
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddresse").set_text(_address)
            else:
                open_hashes[self.resdict.get("forcehash")][0].get_object("chooseaddresse").set_text("")
        return True
        
    def do_requestdo(self,action, **obdict):
        od = self.resdict.copy()
        od.update(obdict)
        return self.links["gtkclient"].do_requestdo(action, **od)
    
    def get_address_list(self):
        ret = []
        for elem in open_hashes[self.resdict.get("forcehash")][1]:
            ret.append(elem)
        return sorted(ret)
    
    def get_traverseaddr(self):
        return self.resdict.get("traverseserveraddr")
    def get_address(self):
        if len(open_hashes[self.resdict.get("forcehash")][1])==0:
            return None
        return self.get_object("chooseaddresse").get_text()
    
    def close(self,*args):
        self.win.hide()
        self.links["gtkclient"].app.remove_window(self.win)
        del open_hashes[self.resdict.get("forcehash")]
        self.win.destroy()
        del self


