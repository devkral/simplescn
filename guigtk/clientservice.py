#! /usr/bin/env python3

import os,sys
#thisdir=os.path.dirname(os.path.realpath(__file__))

from gi.repository import Gtk
from guicommon import gtkclient_template

from common import sharedir,isself


import logging

class gtkclient_remoteservice(gtkclient_template):
    name=None
    def __init__(self,links,_address,dparam,name=""):
        gtkclient_template.__init__(self, links,_address,dparam)
        if self.init2(os.path.join(sharedir, "guigtk", "clientservice.ui"))==False:
            return
        self.win=self.get_object("servicewin")
        self.win.set_title(name)
        
        serviceview=self.builder.get_object("nodeserviceview")
        servicecol = Gtk.TreeViewColumn("Service", Gtk.CellRendererText(), text=0)
        serviceview.append_column(servicecol)
        servicecol2 = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=1)
        serviceview.append_column(servicecol2)
        self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.connect_signals(self)
        self.win.connect('delete-event',self.close)
        self.update()
        
    def update(self,*args):
        servicel=self.builder.get_object("servicelist")
        ret=self.do_requestdo("listservices", self.address)
        if ret[0]==False:
            logging.info(e)
            return
        servicel.clear()
        for elem in ret[1]:
            servicel.append((elem[0],elem[1]))
        
    
    def copy(self,*args):
        view=self.builder.get_object("nodeserviceview")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service="{address}:{port}".format(address=self.address,port=_sel[0][_sel[1]][1])
        self.clip.set_text(service,-1)
        self.win.destroy()
        
    def close(self,*args):
        
        return True
