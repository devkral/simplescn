#! /usr/bin/env python3


from gi.repository import Gtk,Gdk


run=True


class gtkclient_template(Gtk.Builder):
    #builder=None
    links=None
    win=None
    dparam=None
    address=None
    #autoclose=0 #closes window after a timeperiod
    
    def __init__(self,_file,links,_address,dparam):
        Gtk.Builder.__init__(self)
        self.links=links
        self.dparam=dparam
        self.address=_address
        
        self.set_application(links["gtkclient"])
        self.add_from_file(_file)
        
    def do_requestdo(self,action,*requeststrs,parse=-1):
        requeststrs+=(self.dparam,)
        return self.links["gtkclient"].do_requestdo(action,*requeststrs,parse=parse)
    
    def close(self,*args):
        self.win.destroy()
        self.links["gtkclient"].remove_window(self.win)
        del self


