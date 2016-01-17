#! /usr/bin/env python3
# bsd3, see LICENSE.txt

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk

from simplescn.guigtk import clientdialogs

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


