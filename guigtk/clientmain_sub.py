#! /usr/bin/env python3

from common import isself, logger
from gi.repository import Gtk

class services_stuff(object):
    mswin = None
    builder = None
    
    def __init__(self):
        self.mswin = self.builder.get_object("manageserviceswin")
        serviceview=self.builder.get_object("localserviceview")
        servicecol = Gtk.TreeViewColumn("Service", Gtk.CellRendererText(), text=0)
        serviceview.append_column(servicecol)
        servicecol2 = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=1)
        serviceview.append_column(servicecol2)
        
        self.mswin.connect('delete-event',self.close_manages)
    
    def manageservices(self,*args):
        self.update_services()
        self.mswin.show()
        self.mswin.grab_focus()

    def update_services(self,*args):
        localservicelist=self.builder.get_object("localservicelist")
        localservicelist.clear()
        but=self.builder.get_object("deleteserviceb")
        but.hide()
        services=self.do_requestdo("listservices")
        if services[0]==False:
            return
        for elem in services[1]:
            localservicelist.append((elem[0],elem[1]))
    
        
    def add_service(self,*args):
        localservicelist=self.builder.get_object("localservicelist")
        servicee=self.builder.get_object("newservicenameentry")
        porte=self.builder.get_object("newserviceportentry")
        service=servicee.get_text().strip(" ").rstrip(" ")
        port=porte.get_text().strip(" ").rstrip(" ")
        if service=="":
            logger().debug("service invalid")
            return
        if port == "" or port.isdecimal() == False:
            logger().debug("port invalid")
            return
        ret = self.do_requestdo("registerservice", name=service, port=port)
        if ret[0] == False:
            logger().debug(ret[1])
            return
        servicee.set_text("")
        porte.set_text("")
        
        localservicelist.append((service,port))
        
    def sel_service(self,*args):
        view=self.builder.get_object("localserviceview")
        but=self.builder.get_object("deleteserviceb")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            but.hide()
        else:
            but.show()

    def del_service(self,*args):
        view=self.builder.get_object("localserviceview")
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            return
        service=_sel[0][_sel[1]][0]
        if service=="":
            return
        ret=self.do_requestdo("delservice", name=service)
        if ret[0]==False:
            return
        self.update_services()

    def close_manages(self,*args):
        self.mswin.hide()
        return True

class cmd_stuff(object):
    cmdwin = None
    cmd_wintoggle = None
    builder = None
    links = None
    
    def __init__(self):
        self.cmdwin=self.builder.get_object("cmdwin")
        cmdbuffer = self.builder.get_object("cmdbuffer")
        cmdbuffer.create_mark("scroll",cmdbuffer.get_end_iter(),True)
        self.cmd_wintoggle = self.builder.get_object("cmdme")
        self.cmdwin.connect('delete-event',self.close_cmd)
    
    def cmd_do(self,*args):
        cmdveri=self.builder.get_object("cmdveri")
        inp=self.builder.get_object("cmdenter")
        out=self.builder.get_object("cmdbuffer")
        cmdview=self.builder.get_object("cmdview")
        resp = self.links["client"].command(inp.get_text().strip(" ").rstrip(" "))
        if resp[0] == True:
            if resp[2] is None:
                cmdveri.set_text("Unverified")
            elif resp[2] == isself:
                cmdveri.set_text("Is own client")
            else:
                cmdveri.set_text("Verified as: "+resp[2])
            inp.set_text("")
        else:
            out.insert(out.get_end_iter(),"Error:\n")
        out.insert(out.get_end_iter(),resp[1]+"\n")
        out.move_mark_by_name("scroll", out.get_end_iter())
        cmdview.scroll_to_mark(out.get_mark("scroll"),0.4,True,0,1)
        #place_cursor_onscreen()
        #cmdwinscrolla.set_value(0) #100)
    def cmdme(self,*args):
        if self.cmd_wintoggle.get_active()==True:
            self.cmdwin.show()
            self.cmdwin.grab_focus()
            
        else:
            self.cmdwin.hide()
            
    def close_cmd(self,*args):
        self.cmd_wintoggle.set_active(False)
        self.cmdwin.hide()
        return True


class debug_stuff(object):
    debugwin = None
    debugbuffer = None
    debugview = None
    debug_wintoggle = None
    builder = None
    
    def __init__(self):
        self.debugwin=self.builder.get_object("debugwin")
        self.debugbuffer = self.builder.get_object("debugbuffer")
        
        self.debugbuffer.create_mark("scroll",self.debugbuffer.get_end_iter(),True)
        self.debugview = self.builder.get_object("debugview")
        self.debug_wintoggle = self.builder.get_object("debugme")
        
        self.debugwin.connect('delete-event',self.close_debug)
        
    def debugme(self,*args):
        if self.debug_wintoggle.get_active()==True:
            self.debugwin.show()
            self.debugwin.grab_focus()
        else:
            self.debugwin.hide()
            
    def close_debug(self,*args):
        self.debug_wintoggle.set_active(False)
        self.debugwin.hide()
        return True
        
