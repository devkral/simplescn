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
        for elem in services[1]["items"]:
            localservicelist.append((elem[0], str(elem[1])))
    
        
    def add_service(self,*args):
        localservicelist = self.builder.get_object("localservicelist")
        servicee = self.builder.get_object("newservicenameentry")
        porte = self.builder.get_object("newserviceportentry")
        service = servicee.get_text().strip(" ").rstrip(" ")
        port = porte.get_text().strip(" ").rstrip(" ")
        if service=="":
            logger().debug("service invalid")
            return
        if port == "" or port.isdecimal() == False:
            logger().debug("port invalid")
            return
        print("\""+port+"\"")
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

class configuration_stuff(object):
    configurationwin = None
    configuration_wintoggle = None
    builder = None
    links = None
    preflist = None
    pluginlistview = None
    prefview = None
    defaultvall = None
    
    
    _changed_pluginconf = None
    _changed_mainconf = None
    
    def __init__(self):
        self.configurationwin=self.builder.get_object("configurationwin")
        self.configurationwin.connect('delete-event',self.close_configurationwin)
        self._changed_pluginconf = {}
        self._changed_mainconf = {}
        self.preflist = self.builder.get_object("preflist")
        self.defaultvall = self.builder.get_object("defaultvall")
        self.permanentl = self.builder.get_object("permanentl")
        self.loadplugins()
        
        self.pluginlistview = self.builder.get_object("pluginlistview")
        col0 = Gtk.TreeViewColumn("Plugins", Gtk.CellRendererText(), text=0)
        self.pluginlistview.append_column(col0)
        
        self.prefview = self.builder.get_object("prefview")
        col10 = Gtk.TreeViewColumn("Key", Gtk.CellRendererText(), text=0)
        self.prefview.append_column(col10)
        renderer_col11 = Gtk.CellRendererText(editable=True, editable_set=True)
        renderer_col11.connect("edited", self.conf_change_key)
        col11 = Gtk.TreeViewColumn("Value", renderer_col11, text=1)
        self.prefview.append_column(col11)
        
    def configurationme(self,*args):
        self.init_config()
        self.configurationwin.show()
        self.configurationwin.grab_focus()
    
    def set_tainted(self, tainted):
        applybut = self.builder.get_object("applyconfb")
        resetbut = self.builder.get_object("resetconfb")
        applybut.set_sensitive(tainted)
        resetbut.set_sensitive(tainted)
    
    def select_config_row(self, *args):
        _sel=self.prefview.get_selection().get_selected()
        defvar = ""
        permvar = ""
        if _sel[1] is not None:
            defvar = _sel[0][_sel[1]][3]
            if defvar is None:
                defvar = ""
            if _sel[0][_sel[1]][2]:
                permvar = "Permanent: yes"
            else:
                permvar = "Permanent: no"
        self.defaultvall.set_text(defvar)
        self.permanentl.set_text(permvar)
    
    def conf_change_key(self, cell_renderer_text, path, new_text):
        if self.preflist[path][1] == new_text:
            return
        
        useplugin = self.builder.get_object("usepluginconf")

        _key = self.preflist[path][0]
        if useplugin.get_active() == True:
            _selp=self.pluginlistview.get_selection().get_selected()
            if _selp[1] is None:
                return
            _plugin = _selp[0][_selp[1]][0]
            if _plugin not in self._changed_pluginconf:
                self._changed_pluginconf[_plugin] = {}
            self._changed_pluginconf[_plugin][_key] = new_text
        else:
            self._changed_mainconf[_key] = new_text
            
        self.preflist[path][1] = new_text
        self.set_tainted(True)
        #print(cell_renderer_text, path, new_text)
    
    def init_config(self, *args):
        if self.configurationwin.is_visible() == False:
            self.reset_config()

    def reset_config(self, *args):
        self._changed_pluginconf = {}
        self._changed_mainconf = {}
        self.set_tainted(False)
        
        usemaint = self.builder.get_object("usemainconf")
        #useplugt = self.builder.get_object("usepluginconf")
        #prefmainscroll = self.builder.get_object("prefmainscroll")
        
        
        if usemaint.get_active():
            self.load_mainconfig()
        else:
            self.load_pluginconfig
    
    def apply_config(self, *args):
        haderror = False
        for key, val in self._changed_mainconf.items():
            if self.do_requestdo("set_config", key=key, value=val)[0] == False:
                haderror = True
        
        for plugin, kv in self._changed_pluginconf.items():
            for key, val in kv.items():
                if self.do_requestdo("set_pluginconfig", plugin=plugin,  key=key, value=val)[0] == False:
                    haderror = True
        
        if haderror == False:
            self.reset_config()
        #self._changed_pluginconf = {}
        #self._changed_mainconf = {}
        
        #self.set_tainted(False)

    def load_mainconfig(self, *args):
        prefpluginscroll = self.builder.get_object("prefpluginscroll")
        prefpluginscroll.hide()
        
        cleanpluginsb = self.builder.get_object("cleanpluginsb")
        cleanpluginsb.hide()
        
        self.preflist.clear()
        _preflist = self.do_requestdo("list_config")
        if _preflist[0] == False:
            return
        for _key, _val, _default, ispermanent in _preflist[1]["items"]:
            self.preflist.append((_key, _val, ispermanent, _default))
        
    def load_pluginconfig(self, *args):
        self.preflist.clear()
        prefpluginscroll = self.builder.get_object("prefpluginscroll")
        prefpluginscroll.show()
        
        cleanpluginsb = self.builder.get_object("cleanpluginsb")
        cleanpluginsb.show()
        
        self.preflist.clear()
        #localview=self.builder.get_object("localview")
        _sel=self.pluginlistview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _plugin = _sel[0][_sel[1]][0]
        
        _preflist = self.do_requestdo("list_pluginconfig", plugin=_plugin)
        if _preflist[0] == False:
            return
        for _key, _val, _default, ispermanent in _preflist[1]["items"]:
            self.preflist.append((_key, _val, ispermanent, _default))
        
    def use_default_config_key(self, *args):
        _sel=self.prefview.get_selection().get_selected()
        if _sel[1] is None:
            return
        defvar = _sel[0][_sel[1]][3]
        if defvar is None:
            defvar = ""
        #if _sel[0][_sel[1]][1] == _sel[0][_sel[1]][2]:
        #    return
        # renderer, path, defaultval
        self.conf_change_key(None, _sel[1], defvar)
        #self.set_tainted(True)
    
    def loadplugins(self):
        pluginlist= self.builder.get_object("pluginlist")
        pluginlist.clear()
        _listplugins = self.do_requestdo("listplugins")
        if _listplugins[0] == False:
            logger.error(_listplugins[1])
            _listplugins = []
        else:
            _listplugins = _listplugins[1]["items"]
        
        for plugin in _listplugins:
            pluginlist.append((plugin[0], ))
    
    def clean_plugins(self, *args):
        ret = self.do_requestdo("clean_pluginconfig", plugin=_plugin)
        #if ret[0]:
        #    self.loadplugins()
    def toggle_configuration(self,*args):
        usemaint = self.builder.get_object("usemainconf")
        #useplugt = self.builder.get_object("usepluginconf")
        #prefmainscroll = self.builder.get_object("prefmainscroll")
        # show pluginlist with checkbutton for active when usepluginconf is active
        # elsewise show just the configurationwindow
        if usemaint.get_active() == True:
            self.load_mainconfig()
        else:
            self.load_pluginconfig()
            
    def close_configurationwin(self,*args):
        self.configurationwin.hide()
        self.reset_config()
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
        
