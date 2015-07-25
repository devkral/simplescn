
from common import logger, scnparse_url
import logging
from gi.repository import Gtk

from guigtk.clientinfo import gtkclient_info
from guigtk.clientnode import gtkclient_node
from guigtk.clientserver import gtkclient_server


class hashmanagement(object):
    managehashdia = None
    builder = None
    links = None
    
    def __init__(self):
        self.managehashdia = self.builder.get_object("managehashdia")
        
        
        self.managehashdia.connect('delete-event',self.close_managehashdia)

    def activate_local(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        nodeactionset=self.builder.get_object("nodeactionset")
        action_sub=self.builder.get_object("refactiongrid_sub")
        refactiongrid_sub=self.builder.get_object("refactiongrid_sub")
        refscrollwin=self.builder.get_object("refscrollwin")
        
        localview=self.builder.get_object("localview")
        _sel=localview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _name=_sel[0][_sel[1]][0]
        
        parentit=_sel[0].iter_parent(_sel[1])
        if parentit is None:
            self.addentity()
            return
        _type=_sel[0][parentit][0]
        
        if _type=="Server":
            self.curlocal=("server",_name)
        elif _type=="Friend":
            self.curlocal=("client",_name)
        else:
            self.curlocal=("unknown",_name)
        self._intern_node_type="unknown"
        self.update_hashes()
        self.managehashdia.set_title(_name)
        
        nodeactionset.hide()
        refactiongrid_sub.hide()
        refscrollwin.hide()
        self.managehashdia.show()
        
    def update_hashes(self,*args):
        temp=self.do_requestdo("listhashes",self.curlocal[1],self.header_client)
        hashlist=self.builder.get_object("hashlist")
        hashlist.clear()
        if temp[0]==False:
            logger().debug("Exist?")
            return
        for elem in temp[1]:
            if elem[1] is None:
                if elem[0]!="default":
                    logger().info("invalid element: {}".format(elem))
            elif elem[1]==self.curlocal[0]:
                hashlist.append((elem[0],))
        
    def select_hash(self,*args):
        view=self.builder.get_object("hashview")
        action_sub=self.builder.get_object("refactiongrid_sub")
        refscrollwin=self.builder.get_object("refscrollwin")
        
        updatereftb=self.builder.get_object("updatereftb")
        addrefb=self.builder.get_object("addrefb")
        addrefentry=self.builder.get_object("addrefentry")
        
        
        _sel=view.get_selection().get_selected()
        reflist=self.builder.get_object("reflist")
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
    
    def select_ref(self,*args):
        view=self.builder.get_object("refview")
        nodeactionset=self.builder.get_object("nodeactionset")
        
        
        addrefb=self.builder.get_object("addrefb")
        delrefb=self.builder.get_object("delrefb")
        updatereftb=self.builder.get_object("updatereftb")
        
        addrefentry=self.builder.get_object("addrefentry")
        
        
        updatereftb.set_active(False)
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            nodeactionset.hide()
            delrefb.set_sensitive(False)
            updatereftb.set_sensitive(False)
            return
        #updaterefentry.set_text(_sel[0][_sel[1]][1])
        nodeactionset.show()
        delrefb.set_sensitive(True)
        updatereftb.set_sensitive(True)
        
        addrefentry.hide()
        addrefb.show()
        
        
    def update_refs(self,*args):
        hview=self.builder.get_object("hashview")
        _sel=hview.get_selection().get_selected()
        if _sel[1] is None:
            return
        _hash=_sel[0][_sel[1]][0]
    
        temp=self.do_requestdo("getreferences",_hash,self.header_client)
        reflist=self.builder.get_object("reflist")
        reflist.clear()
        if temp[0]==False:
            logger().debug("Exist?")
            return
        for elem in temp[1]:
            reflist.append((elem[0],elem[1]))
    
    # update node type then open node 
    def action__node(self, action):
        servercombo = self.builder.get_object("servercomboentry")
        rview = self.builder.get_object("refview")
        _selr=rview.get_selection().get_selected()
        if _selr[1] is None:
            return
        _ref, _type=_selr[0][_selr[1]]
        
        
        hview = self.builder.get_object("hashview")
        _selh=hview.get_selection().get_selected()
        if _selh[1] is None:
            return
        _hash=_selh[0][_selh[1]][0]
        serverurl = None
        
        if _type == "name":
            serverurl = servercombo.get_text().strip(" ").rstrip(" ")
            if serverurl=="":
                logger().info("no server selected")
                return
            
            turl=self.do_requestdo("get", serverurl, _ref, _hash, self.header_server)
            if logger().check(turl, logging.INFO)==False:
                return
            _url="{}:{}".format(*turl[1])
        elif _type == "surl":
            serverurl=_ref
            namesret=self.do_requestdo("getreferences",_hash, "name",self.header_server)
            if namesret[0]==False:
                logger().info("getrefences failed")
                return
            tempret=None
            for elem in namesret[1]: #try all names
                if elem[0] in ["", None]:
                    logger().warn("references type name contain invalid element: {}".format(elem[0]))
                else:
                    tempret=self.do_requestdo("get",serverurl,elem[0],_hash,self.header_server)
                    if tempret[0]==True:
                        break
            if tempret is None or logger().check(tempret, logging.INFO)==False:
                return
            _url="{}:{}".format(*tempret[1])
        elif _type == "url":
            _url=_ref
        else:
            logger().info("invalid type")
            return
        if ":"  not in _url:
            logger().info("invalid url: {}".format(_url))
            return
        
        tdparam=self.header_node.copy()
        tdparam["certhash"]=_hash
        
        ret=self.do_requestdo("check_direct", _url, self.curlocal[1], _hash,tdparam)
        if ret[0]==True:
            self.managehashdia.hide()
            if self.curlocal[0] == "server":
                servercombo.set_text(_url)
                self.veristate_server()
            else:
                self.set_curnode(_url, self.curlocal[1], _hash, serverurl)
            # TODO: use enum
            if action == 0:
                pass
            elif action == 1:
                if self.curlocal[0] == "server":
                    gtkclient_server(self.links,"{}:{}".format(*scnparse_url(_url)),tdparam, self.curlocal[1])
                else:
                    gtkclient_node(self.links,"{}:{}".format(*scnparse_url(_url)),tdparam, self.curlocal[1])
            elif action == 2:
                gtkclient_info(self.links,"{}:{}".format(*scnparse_url(_url)),tdparam,self.curlocal[1])
        else:
            logger().error(ret[1])
    
    def select_node(self, action):
        self.action__node(0)
        
    def get_node(self, action):
        self.action__node(1)
    
    def info_node(self, action):
        self.action__node(1)
        
    def close_managehashdia(self,*args):
        self.managehashdia.hide()
        return True
