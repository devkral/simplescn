#! /usr/bin/env python3

import os,sys
#thisdir=os.path.dirname(os.path.realpath(__file__))

from gi.repository import Gtk, Gdk
from guigtk.guicommon import gtkclient_template

from common import sharedir,isself


import logging

class gtkclient_remoteservice(gtkclient_template):
    name=None
    def __init__(self,links,_address,dheader,name=""):
        gtkclient_template.__init__(self, links,_address,dheader)
        if self.init2(os.path.join(sharedir, "guigtk", "clientservice.ui"))==False:
            return
        self.win=self.get_object("servicewin")
        if name is isself:
            self.win.set_title("This client")
        else:
            self.win.set_title(name)
        
        serviceview=self.get_object("nodeserviceview")
        servicecol = Gtk.TreeViewColumn("Service", Gtk.CellRendererText(), text=0)
        serviceview.append_column(servicecol)
        servicecol2 = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=1)
        serviceview.append_column(servicecol2)
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.connect_signals(self)
        self.win.connect('delete-event',self.close)
        self.update()
        
    def update(self,*args):
        servicel=self.get_object("servicelist")
        ret=self.do_requestdo("listservices", self.address)
        if ret[0]==False:
            logging.info(ret[1])
            return
        servicel.clear()
        for elem in ret[1]:
            servicel.append((elem[0],elem[1]))
        
    
    def copy(self,*args):
        view=self.get_object("nodeserviceview")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service="{address}:{port}".format(address=self.address.rsplit(":",1)[0],port=_sel[0][_sel[1]][1])
        self.clip.set_text(service,-1)
        self.close()
        
