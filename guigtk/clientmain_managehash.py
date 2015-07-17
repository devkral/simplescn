from common import logger
from gi.repository import Gtk


class hashmanagement(object):
    managehashdia = None
    builder = None
    
    def __init__(self):
        self.managehashdia = self.builder.get_object("managehashdia")
        
        
        self.managehashdia.connect('delete-event',self.close_managehashdia)

    def activate_local(self,*args):
        serverurl=self.builder.get_object("servercomboentry").get_text()
        getnodebut=self.builder.get_object("getnodebut")
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
        
        getnodebut.hide()
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
        getnodebut=self.builder.get_object("getnodebut")
        
        
        addrefb=self.builder.get_object("addrefb")
        delrefb=self.builder.get_object("delrefb")
        updatereftb=self.builder.get_object("updatereftb")
        
        addrefentry=self.builder.get_object("addrefentry")
        
        
        updatereftb.set_active(False)
        _sel=view.get_selection().get_selected()
        if _sel[1] is None:
            getnodebut.hide()
            delrefb.set_sensitive(False)
            updatereftb.set_sensitive(False)
            return
        #updaterefentry.set_text(_sel[0][_sel[1]][1])
        getnodebut.show()
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

    def close_managehashdia(self,*args):
        self.managehashdia.hide()
        return True
