#! /usr/bin/env python3
# bsd3, see LICENSE.txt

import os, sys
import subprocess
import gi
import logging
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GdkPixbuf, GLib, Gdk

basedir = os.path.dirname(__file__)
parentlist = []

def get_parent():
    """ func: return toplevel window
        return: toplevel window """
    if len(parentlist) == 0:
        return None
    return parentlist[-1]

def _gtkclient_notify(msg, requester=""):
    """ func: gtk notification dialog
        return: True or False
        requester: plugin which requests the dialog (None: for main) """
    icon = GdkPixbuf.Pixbuf.new_from_file(os.path.join(basedir, "icon.svg"))
    if icon:
        dia = Gtk.Dialog(parent=None, title="Notify", icon=icon)
    else:
        dia = Gtk.Dialog(parent=None, title="Notify")
    dia.add_button("Confirm", 1)
    dia.add_button("Cancel", 0)
    box = dia.get_content_area()
    if requester not in ["", None]:
        labelreq = Gtk.Label("{} asks:".format(requester))
        #dia.set_title(requester)
        box.pack_start(labelreq, False, False, 0)
    box.pack_end(Gtk.Label(msg), True, True, 0)
    box.show_all()
    dia.present()
    ret = dia.run() > 0
    dia.destroy()
    #ret[1].release()
    return ret
    
def gtkclient_notify(msg, requester=""):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    if requester is None:
        requester = ""
    with subprocess.Popen([sys.executable, __file__, "notify", msg, requester], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate()[0][:-1], "utf-8")

def _gtkclient_pw(msg, requester=""):
    """ func: gtk password dialog
        return: None or pw
        requester: plugin which requests the dialog (None: for main)
    """
    icon = GdkPixbuf.Pixbuf.new_from_file(os.path.join(basedir, "icon.svg"))
    if icon:
        dia = Gtk.Dialog(title="Password", parent=None, icon=icon, destroy_with_parent=False)
    else:
        dia = Gtk.Dialog(title="Password", parent=None, destroy_with_parent=False)
    dia.add_button("Confirm", 1)
    dia.add_button("Cancel", 0)
    box = dia.get_content_area()
    if requester not in ["", None]:
        labelreq = Gtk.Label("{} requests pw for:\n{}".format(requester, msg))
        box.pack_start(labelreq, False, False, 0)
    box.pack_end(Gtk.Label(msg), True, True, 0)
        
    pwentry = Gtk.Entry(input_purpose=Gtk.InputPurpose.PASSWORD, invisible_char="*", hexpand=True)
    box.pack_end(pwentry, True, True, 0)
    box.show_all()
    dia.present()
    
    retval = dia.run()
    pw = pwentry.get_text()
    dia.destroy()
    
    if retval == 1:
        return pw
    else:
        return ""


def gtkclient_pw(msg, requester=""):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    if requester is None:
        requester = ""
    with subprocess.Popen([sys.executable, __file__, "pw", msg, requester], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate()[0][:-1], "utf-8")
    

if __name__ == "__main__":
    if sys.argv[1] == "pw":
        print(_gtkclient_pw(sys.argv[2], sys.argv[3]))
        sys.exit(0)
    elif sys.argv[1] == "notify":
        print(str(_gtkclient_notify(sys.argv[2], sys.argv[3])))
        sys.exit(0)
    while True:
        Gtk.main_iteration_do(True)
