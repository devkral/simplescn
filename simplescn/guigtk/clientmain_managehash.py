"""
hashmanagement for gtk gui
license: MIT, see LICENSE.txt
"""

import logging
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

from simplescn import scnparse_url, logcheck
from simplescn.guigtk.clientnode import gtkclient_node
from simplescn.guigtk import implementedrefs

class hashmanagement(object):
    managehashdia = None
    builder = None
    links = None
    _intern_node_type = None
    curlocal = None

    def init(self):
        hview = self.builder.get_object("hashview")
        rview = self.builder.get_object("refview")
        hcol1 = Gtk.TreeViewColumn("Node", Gtk.CellRendererText(), text=0)
        rcol1 = Gtk.TreeViewColumn("Reference", Gtk.CellRendererText(), text=0)
        rcol2 = Gtk.TreeViewColumn("Type", Gtk.CellRendererText(), text=1)
        hview.append_column(hcol1)
        rview.append_column(rcol1)
        rview.append_column(rcol2)
        self.managehashdia = self.builder.get_object("managehashdia")
        #self.managehashdia.set_transient_for(self.win)
        self.managehashdia.connect('delete-event', self.close_managehashdia)

    def activate_local(self, *args):
        nodeactionset = self.builder.get_object("nodeactionset")
        refactiongrid_sub = self.builder.get_object("refactiongrid_sub")
        refscrollwin = self.builder.get_object("refscrollwin")
        localview = self.builder.get_object("localview")
        _sel = localview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name = _sel[0][_sel[1]][0]

        parentit = _sel[0].iter_parent(_sel[1])
        if parentit is None:
            self.addentity()
            return
        _type = _sel[0][parentit][0]

        if _type == "Server":
            self.curlocal = ("server", _name)
        elif _type == "Friend":
            self.curlocal = ("client", _name)
        else:
            self.curlocal = ("unknown", _name)
        self._intern_node_type = "unknown"
        self.update_hashes()
        self.managehashdia.set_title(_name)

        nodeactionset.hide()
        refactiongrid_sub.hide()
        refscrollwin.hide()
        self.managehashdia.show()

    def update_hashes(self, *args):
        temp = self.do_requestdo("listhashes", name=self.curlocal[1])
        hashlist = self.builder.get_object("hashlist")
        hashlist.clear()
        if not temp[0]:
            logging.debug("Exist?")
            return
        for elem in temp[1]["items"]:
            if elem[1] is None:
                if elem[0] != "default":
                    logging.info("invalid element: %s", elem)
            elif elem[1] == self.curlocal[0]:
                hashlist.append((elem[0],))

    def select_hash(self, *args):
        view = self.builder.get_object("hashview")
        action_sub = self.builder.get_object("refactiongrid_sub")
        refscrollwin = self.builder.get_object("refscrollwin")

        addrefb = self.builder.get_object("addrefb")
        addrefentry = self.builder.get_object("addrefentry")
        _sel = view.get_selection().get_selected()
        reflist = self.builder.get_object("reflist")
        reflist.clear()

        if _sel[1] is None:
            action_sub.hide()
            refscrollwin.hide()
            return

        action_sub.show()
        addrefentry.hide()
        addrefb.show()
        refscrollwin.show()
        self.update_refs()

    def select_ref(self, *args):
        view = self.builder.get_object("refview")
        nodeactionset = self.builder.get_object("nodeactionset")
        addrefb = self.builder.get_object("addrefb")
        delrefb = self.builder.get_object("delrefb")
        updatereftb = self.builder.get_object("updatereftb")
        addrefentry = self.builder.get_object("addrefentry")
        updatereftb.set_active(False)
        _sel = view.get_selection().get_selected()
        if _sel[1] is None:
            nodeactionset.hide()
            delrefb.set_sensitive(False)
            updatereftb.set_sensitive(False)
            return
        nodeactionset.show()
        delrefb.set_sensitive(True)
        updatereftb.set_sensitive(True)
        addrefentry.hide()
        addrefb.show()

    def update_refs(self, *args):
        hview = self.builder.get_object("hashview")
        _sel = hview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _hash = _sel[0][_sel[1]][0]
        temp = self.do_requestdo("getreferences", hash=_hash)
        reflist = self.builder.get_object("reflist")
        reflist.clear()
        if not temp[0]:
            logging.debug("Exist?")
            return
        reflist.append(("None", "None")) #special for just open node
        for elem in temp[1]["items"]:
            reflist.append((elem[0], elem[1]))

    # update node type then open node
    def action_node(self, justselect):
        servercombo = self.builder.get_object("servercomboentry")
        rview = self.builder.get_object("refview")
        _selr = rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref, _type = _selr[0][_selr[1]]
        hview = self.builder.get_object("hashview")
        _selh = hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash = _selh[0][_selh[1]][0]
        serverurl = None

        if _type == "name":
            serverurl = servercombo.get_text().strip(" ").rstrip(" ")
            if serverurl == "":
                logging.info("no server selected")
                return

            turl = self.do_requestdo("get", server=serverurl, reference=_ref, hash=_hash)
            if not logcheck(turl, logging.INFO):
                return
            _url = "{address}-{port}".format(**turl[1])
        elif _type == "surl":
            serverurl = _ref
            namesret = self.do_requestdo("getreferences", hash=_hash, type="name")
            if not logcheck(namesret, logging.INFO):
                return
            tempret = None
            for elem in namesret[1]["items"]: #try all names
                if elem[0] in ["", None]:
                    logging.warning("references type name contain invalid element: %s", elem[0])
                else:
                    tempret = self.do_requestdo("get", server=serverurl, name=elem[0], hash=_hash)
                    if tempret[0]:
                        break
            if tempret is None or not logcheck(tempret, logging.INFO):
                return
            _url = "{address}-{port}".format(**tempret[1])
        elif _type == "url":
            _url = _ref
        elif _type == "None":
            _url = None
        elif _type in implementedrefs:
            return
        else:
            logging.info("invalid type")
            return
        if _url is not None and "-"  not in _url:
            logging.info("invalid url: %s", _url)
            return

        if _url is None:
            ret = [True]
        else:
            ret = self.do_requestdo("check_direct", address=_url, name=self.curlocal[1], hash=_hash, forcehash=_hash)

        if logcheck(ret, logging.ERROR):
            self.managehashdia.hide()
            if _url:
                if self.curlocal[0] == "server":
                    servercombo.set_text(_url)
                    self.veristate_server()
                else:
                    self.set_curnode(_url, self.curlocal[1], _hash, serverurl)
            if justselect:
                pass
            elif _url is None:
                gtkclient_node(self.links, None, forcehash=_hash, page=1)
            else:
                gtkclient_node(self.links, "{}-{}".format(*scnparse_url(_url)), forcehash=_hash, page=1)

    def select_node(self, action):
        self.action_node(True)

    def get_node(self, action):
        self.action_node(False)

    def close_managehashdia(self, *args):
        self.managehashdia.hide()
        return True
