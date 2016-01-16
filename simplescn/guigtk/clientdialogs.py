
# bsd3, see LICENSE.txt

import os
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GdkPixbuf

basedir = os.path.dirname(__file__)

parentlist = []

def get_parent():
    """ func: return toplevel window
        return: toplevel window """
    if len(parentlist) == 0:
        return None
    return parentlist[-1]

def gtkclient_notify(msg, requester=None):
    """ func: gtk notification dialog
        return: True or False
        requester: plugin which requests the dialog (None: for main) """
    icon = GdkPixbuf.Pixbuf.new_from_file(os.path.join(basedir, "icon.png"))
    if icon:
        dia = Gtk.Dialog(parent=get_parent(), title="Notify", icon=icon)
    else:
        dia = Gtk.Dialog(parent=get_parent(), title="Notify")
    dia.add_button("Confirm", 1)
    dia.add_button("Cancel", 0)
    box = dia.get_content_area()
    if requester:
        labelreq = Gtk.Label("{} asks:".format(requester))
        #dia.set_title(requester)
        box.pack_start(labelreq, False, False, 0)
    box.pack_end(Gtk.Label(msg), True, True, 0)
    box.show_all()
    dia.present()
    ret = dia.run() > 0
    dia.destroy()
    return ret
    

def gtkclient_pw(msg, requester=None):
    """ func: gtk password dialog
        return: None or pw
        requester: plugin which requests the dialog (None: for main)
    """
    icon = GdkPixbuf.Pixbuf.new_from_file(os.path.join(basedir, "icon.png"))
    if icon:
        dia = Gtk.Dialog(title="Password", parent=get_parent(), icon=icon, destroy_with_parent=False)
    else:
        dia = Gtk.Dialog(title="Password", parent=get_parent(), destroy_with_parent=False)
    dia.add_button("Confirm", 1)
    dia.add_button("Cancel", 0)
    box = dia.get_content_area()
    if requester:
        labelreq = Gtk.Label("{} requests pw for:\n{}".format(requester, msg))
        box.pack_start(labelreq, False, False, 0)
    box.pack_end(Gtk.Label(msg), True, True, 0)
        
    pwentry = Gtk.Entry(input_purpose=Gtk.InputPurpose.PASSWORD, invisible_char="*", hexpand=True)
    box.pack_end(pwentry, True, True, 0)
    box.show_all()
    dia.present()
    ret = dia.run()
    pw = pwentry.get_text()
    dia.destroy()
    if ret == 1:
        return pw
    else:
        return ""
