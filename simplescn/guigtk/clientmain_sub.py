#! /usr/bin/env python3
# bsd3, see LICENSE.txt

import logging
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
try:
    import markdown
    gi.require_version('WebKit2', '4.0')
    from gi.repository import WebKit2 
except ImportError:
    pass

from simplescn import isself, logcheck

class configuration_stuff(object):
    win = None
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
        self.configurationwin = self.builder.get_object("configurationwin")
        self.configurationwin.set_transient_for(self.win)
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
        self.configurationwin.present()
        self.configurationwin.set_accept_focus(True)
    
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
            if logcheck(self.do_requestdo("set_config", key=key, value=val), logging.ERROR) == False:
                haderror = True
        
        for plugin, kv in self._changed_pluginconf.items():
            for key, val in kv.items():
                if logcheck(self.do_requestdo("set_pluginconfig", plugin=plugin,  key=key, value=val), logging.ERROR) == False:
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
        if logcheck(_preflist, logging.ERROR) == False:
            return
        for _key, _val, _converter, _default, _doc, ispermanent in _preflist[1]["items"]:
            if _key != "state":
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
        if logcheck(_preflist, logging.ERROR) == False:
            return
        
        for _key, _val, _converter, _default, _doc, ispermanent in _preflist[1]["items"]:
            if _key == "state":
                self.preflist.prepend((_key, _val, ispermanent, _default))
            else:
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
        if logcheck(_listplugins, logging.ERROR) == False:
            _listplugins = []
        else:
            _listplugins = _listplugins[1]["items"]
        
        for plugin in _listplugins:
            pluginlist.append((plugin[0], ))
    
    def clean_plugins(self, *args):
        logcheck(self.do_requestdo("clean_pluginconfig"), logging.ERROR) #plugin=_plugin needed?
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
    win = None
    cmdwin = None
    builder = None
    links = None
    
    def __init__(self):
        self.cmdwin = self.builder.get_object("cmdwin")
        self.cmdwin.set_transient_for(self.win)
        cmdbuffer = self.builder.get_object("cmdbuffer")
        cmdbuffer.create_mark("scroll",cmdbuffer.get_end_iter(),True)
        self.cmdwin.connect('delete-event',self.close_cmd)
    
    def cmd_do(self,*args):
        cmdveri = self.builder.get_object("cmdveri")
        inp = self.builder.get_object("cmdenter")
        out = self.builder.get_object("cmdbuffer")
        cmdview = self.builder.get_object("cmdview")
        resp = self.links["client"].command(inp.get_text().strip(" ").rstrip(" "))
        if resp[0] == True:
            if resp[2] is None:
                cmdveri.set_text("Unverified")
            elif resp[2] == isself:
                cmdveri.set_text("Is own client")
            else:
                cmdveri.set_text("Verified as: "+resp[2][0]+"(resp[2][1])")
            inp.set_text("")
        else:
            out.insert(out.get_end_iter(),"Error:\n")
        out.insert(out.get_end_iter(), str(resp[1])+"\n")
        out.move_mark_by_name("scroll", out.get_end_iter())
        cmdview.scroll_to_mark(out.get_mark("scroll"),0.4,True,0,1)
    
    def cmd_show(self,*args):
        if self.cmdwin.is_visible() == True:
            self.cmdwin.present()
            self.cmdwin.set_accept_focus(True)
            
        else:
            self.cmdwin.show()
            
    def close_cmd(self,*args):
        self.cmdwin.hide()
        return True


class debug_stuff(object):
    win = None
    debugwin = None
    debugview = None
    backlogdebug = None
    debugfilter = None
    builder = None
    
    def __init__(self):
        self.debugwin = self.builder.get_object("debugwin")
        self.debugwin.set_transient_for(self.win)
        
        self.debugview = self.builder.get_object("debugview")
        col10 = Gtk.TreeViewColumn("Message", Gtk.CellRendererText(), text=0)
        self.debugview.append_column(col10)
        self.backlogdebug = self.builder.get_object("backlogdebug")
        
        self.debugfilter = self.builder.get_object("debugfilter")
        self.debugfilter.set_visible_func(self.debug_visible_func)
        filterlevelcombo = self.builder.get_object("filterlevel")
        for name in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            filterlevelcombo.append_text(name)
        self.builder.get_object("filterlevel-entry").set_text(logging.getLevelName(self.links["config"].get("loglevel")))
        self.debugwin.connect('delete-event', self.close_debug)
    
    
    
    def debugfilter_refilter(self,*args):
        self.debugfilter.refilter()
    
    def debug_visible_func(self,_model,_iter,_data):
        _levelname = self.builder.get_object("filterlevel-entry").get_text()
        _levelno = logging._nameToLevel.get(_levelname, 0)
        _search = self.builder.get_object("searchdebug").get_text()
        if _model[_iter] is None:
            return False
        if _search not in _model[_iter][0]:
            return False
        # is debuglevel too low
        if _levelno > _model[_iter][2]:
            return False
        return True

    def present_debug_bt(self, *args):
        _sel = self.debugview.get_selection().get_selected()
        if _sel[1] is None:
            if self.backlogdebug.get_iter_first ():
                _bt = self.backlogdebug[self.backlogdebug.get_iter_first ()][1]
            else:
                _bt = ""
        else:
            _bt=_sel[0][_sel[1]][1]
        self.builder.get_object("showbt").get_buffer().set_text(_bt, len(_bt))
    
    def set_loglevel(self, *args):
        _levelname = self.builder.get_object("filterlevel-entry").get_text()
        _levelno = logging._nameToLevel[_levelname]
        logcheck(self.do_requestdo("changeloglevel", loglevel=_levelno))
        
    def debug_show(self,*args):
        self.debugwin.show()
        self.debugwin.present()
        self.debugwin.set_accept_focus(True)
        #self.render_debug()
            
    def close_debug(self,*args):
        self.debugwin.hide()
        return True

class help_stuff(object):
    aboutwin = None
    helpwin = None
    builder = None
    
    def __init__(self):
        self.aboutwin = self.builder.get_object("aboutwin")
        self.aboutwin.set_transient_for(self.win)
        self.aboutwin.connect('delete-event', self.close_about)
        self.helpwin = self.builder.get_object("helpwin")
        self.helpwin.set_transient_for(self.win)
        _help = self.do_requestdo("help", forcelocal=True)
        if "markdown" in globals() and "WebKit2" in globals():
            view = WebKit2.WebView(editable=False, hexpand=True, vexpand=True)
            wksettings = view.get_settings()
            wksettings.set_property('enable-plugins', False)
            
            view.load_html((markdown.markdown(_help[1]["help"])))
            self.builder.get_object("helpscrollwin").add(view)
            
        else:
            textview = Gtk.TextView(editable=False, hexpand=True, vexpand=True)
            textview.get_buffer().set_text(_help[1]["help"])
            self.builder.get_object("helpscrollwin").add(textview)
        self.builder.get_object("helpscrollwin").show_all()
        self.helpwin.connect('delete-event',self.close_help)
        
    def about_show(self,*args):
        self.aboutwin.show()
        self.aboutwin.present()
        self.aboutwin.set_accept_focus(True)

            
    def close_about(self,*args):
        self.aboutwin.hide()
        return True
    
    
    def help_show(self, *args):
        self.helpwin.show()
        self.helpwin.present()
        self.helpwin.set_accept_focus(True)
        
    def close_help(self,*args):
        self.helpwin.hide()
        return True

