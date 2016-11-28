#! /usr/bin/env python3
"""
dialogs for gtk gui
license: MIT, see LICENSE.txt
"""

import os
import sys
import subprocess
import logging

basedir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

import gi
gi.require_version('Gtk', '3.0')

def pwcallmethod(msg):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    with subprocess.Popen([sys.executable, __file__], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate(bytes(msg, "utf-8"))[0][:-1], "utf-8")

if __name__ == "__main__":
    from gi.repository import Gtk, GdkPixbuf

    def _gtk_pw(msg):
        """ func: gtk password dialog
            return: "" or pw
        """
        #while Gtk.main_iteration_do(True):
        #    pass
        #app = Gtk.Application.new(None, Gio.ApplicationFlags. FLAGS_NONE)app.register()
        #app.add_window(self.win)
        icon = GdkPixbuf.Pixbuf.new_from_file(os.path.join(basedir, "icon.svg"))
        if icon:
            dia = Gtk.Dialog(title="Password", parent=None, icon=icon, destroy_with_parent=False)
        else:
            dia = Gtk.Dialog(title="Password", parent=None, destroy_with_parent=False)
        dia.add_button("Confirm", 1)
        dia.add_button("Cancel", 0)
        box = dia.get_content_area()
        box.pack_start(Gtk.Label(msg), True, True, 0)

        pwentry = Gtk.Entry(input_purpose=Gtk.InputPurpose.PASSWORD, visibility=False, invisible_char="*", hexpand=True)
        box.pack_start(pwentry, True, True, 0)
        box.show_all()
        dia.present()
        retval = dia.run()
        pw = pwentry.get_text()
        dia.destroy()
        if retval == 1:
            return pw
        else:
            return ""

    print(_gtk_pw(input()))
    sys.exit(0)
