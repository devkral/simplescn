

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango, Gio, GLib, GdkPixbuf

#from plugins.chat.main import create_timestamp, parse_timestamp, unparse_timestamp
from .main import create_timestamp, parse_timestamp
#, unparse_timestamp

import threading
import os
import hashlib
import shutil
import logging


def myListBoxCreateWidgetFunc(item, **userdata):
    return item

class gtkstuff(object):
    parent = None
    def __init__(self, parent):
        self.parent = parent
    
    def glist_add_certhash(self, certhash, func, *args):
        Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, self._glist_add_certhash, certhash, func, *args)
    def _glist_add_certhash(self, certhash, func, *args):
        self.parent.sessions[certhash].buffer_gui.append(func(*args))

    def gtk_create_textob(self, isowner, isprivate, timestamp, _text):
        #timest = timestamp.strftime("%Y.%m.%d %H:%M:%S")
        ret = Gtk.Label(_text, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, selectable=True)
    
        if isowner:
            ret.set_halign(Gtk.Align.END)
            ret.set_justify(Gtk.Justification.RIGHT)
            if isprivate:
                ret.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.5, green=0.3, blue=0.0, alpha=1.))
            else:
                ret.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=0.6, blue=0.3, alpha=1.))
            
        else:
            ret.set_halign(Gtk.Align.START)
            ret.set_justify(Gtk.Justification.LEFT)
            if isprivate:
                ret.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=1.))
            else:
                ret.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.7, blue=0.6, alpha=1.))
        return ret


    def gtk_create_imgob(self, isowner, isprivate, timestamp, _img):
        #timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
        # now set to scale down
        
        newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
        newimg.write(_img)
        newimg.close()
        newimg = newimg.get_pixbuf()
        newimg = newimg.scale_simple(100, 100, GdkPixbuf.InterpType.BILINEAR)
        newimg = Gtk.Image.new_from_pixbuf(newimg)
        newimg.set_can_focus(False)
        if isowner:
            newimg.set_halign(Gtk.Align.END)
            if isprivate>0:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
            else:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
        else:
            newimg.set_halign(Gtk.Align.START)
            if isprivate>0:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=0.9))
            else:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=0.7))
        return newimg

    def gtk_download(self, widget, _addressfunc, _traversefunc, certhash, filename, size, pos=0):
        _filech = Gtk.FileChooserDialog(title="Save to file", parent=widget.get_toplevel(), select_multiple=False, action=Gtk.FileChooserAction.SAVE, buttons=("Save", 10, "Cancel", 20))
        #filech.set_filename(os.path.join filename)
        retrun = _filech.run()
        if retrun != 10:
            _filech.destroy()
            return
        _file2 = _filech.get_filename()
        _filech.destroy()
        _socket, _cert, _hash = self.parent.session[certhash].request("fetch_file", "/{filename}/{pos}".format(filename=filename, pos=pos), _traversefunc())
        if _socket is None:
            logging.error("fetching file failed")
            return
        
        if os.path.exists(_file2) and pos > 0:
            _omode = "r+b"
        else:
            _omode = "wb"
        with open(_file2, _omode) as wrio:
            if _omode == "r+b":
                wrio.seek(pos)
            while pos < size - 1024:
                _data = _socket.recv(1024)
                wrio.write(_data)
                pos += len(_data)
            wrio.write(_socket.recv(size - pos))
        self.parent.session[certhash].remove_download(filename)


    def gtk_create_fileob(self, isowner, isprivate, timestamp, filename, size, _addressfunc, _traversefunc, certhash):
        #timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
        ret = Gtk.Grid()
        if isowner:
            ret.attach_next_to(Gtk.Label("Offer File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
            ret.set_halign(Gtk.Align.END)
        else:
            ret.attach_next_to(Gtk.Label("File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
            downbut = Gtk.Button("Download ({} KB)".format(size // 1024))
            downbut.connect("clicked", self.gtk_download, _addressfunc, _traversefunc, certhash, filename, size)
            ret.attach_next_to(downbut, None, Gtk.PositionType.RIGHT, 1, 1)
            ret.set_halign(Gtk.Align.START)
        ret.show_all()
        return ret
        
    def gtk_scroll_down(self, widget, child_prop, scroller):
        if isinstance(widget, Gtk.ListBox): # and scroller.get_value()<10:
            scroller.set_value(100)
    
    def update_private_select(self, widget, certhash):
        privateselect = widget.get_text()
        if privateselect == "public":
            self.parent.sessions[certhash].private = 0
        elif privateselect == "private":
            self.parent.sessions[certhash].private = 1
        elif privateselect == "sensitive":
            self.parent.sessions[certhash].private = 2
        if privateselect != "sensitive":
            self.parent.sessions[certhash].clear_sensitive()
        self.update_private(certhash)

    def gtk_send_text(self, widget, _textwidget, _addressfunc, _traversefunc, certhash):
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
        _text = _textwidget.get_text()
        
        saveob = {}
        saveob["timestamp"] = create_timestamp()
        saveob["private"] = self.parent.sessions[certhash].private
        saveob["owner"] = True
        saveob["type"] = "text"
        saveob["text"] = _text
        
        
        _textb = bytes(_text, "utf-8")
        if len(_textb) == 0:
            return True
        sock, _cert, _hash = self.parent.sessions[certhash].request("send_text", "/{size}".format(size=len(_textb)))

        if sock is None and self.parent.sessions[certhash].private>0:
            logging.error("request failed")
            return False
        elif sock is None:
            # if not private
            self.parent.sessions[certhash].send("send_text", "/{size}".format(size=len(_textb)), _textb)
            
        else:
            sock.sendall(_textb)
            sock.close()
        self.parent.sessions[certhash].add(saveob)
        _textwidget.set_text("")

    def gtk_send_file(self, widget, _addressfunc, _traversefunc, window, certhash):
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
        _filech = Gtk.FileChooserDialog(title="Select file", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("Open",10, "Cancel",20))
        if _filech.run()!=10:
            _filech.destroy()
            return
        _filename = _filech.get_filename()
        _filech.destroy()
        _newname = os.path.basename(_filename)
        if _newname[0] == ".":
            _newname = _newname[1:]
        _size = os.stat(_filename).st_size
        shutil.copyfile(_filename, os.path.join(self.parent.sessions[certhash], "tosend", _newname))
        
        saveob = {}
        saveob["timestamp"] = create_timestamp()
        saveob["private"] = self.parent.sessions[certhash].private
        saveob["owner"] = True
        saveob["type"] = "file"
        saveob["size"] = _size
        saveob["name"] = _newname
        self.parent.sessions[certhash].add(saveob)
        sock, _cert, _hash = self.parent[certhash].request("send_file","/{name}/{size}".format(name=_newname, size=_size))
        if sock is None:
            logging.error("Cannot connect/other error")
            return

    def gtk_send_img(self, widget, _addressfunc, _traversefunc, window, certhash):
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
        _filech = Gtk.FileChooserDialog(title="Select image", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("Open", 10, "Cancel", 20))
        runst = _filech.run()
        _filech.hide()
        if runst != 10:
            _filech.destroy()
            return
        _filename = _filech.get_filename()
        _filech.destroy()
        with open(_filename, "rb") as imgo:
            _img = imgo.read()
        
        newimg = GdkPixbuf.PixbufLoader()
        newimg.write(_img)
        newimg.close()
        newimg = newimg.get_pixbuf()
        # save in original size
        _img2 = newimg.save_to_bufferv("jpeg", ("quality", None), ("75",))
        if _img2[0] == False:
            return
        else:
            _img2 = _img2[1]
        if len(_img2) > self.parent.config.get("maxsizeimg")*1024:
            logging.info("Image too big")
            return
        _imgname = hashlib.sha256(_img2).hexdigest()+".jpg"
        _imgname = os.path.join(self.parent.sessions[certhash].sessionpath, "images", _imgname)
        if not os.path.exists(_imgname) and self.parent.sessions[certhash].private > 0:
            with open(_imgname, "wb") as wobj:
                wobj.write(_img2)
            
        saveob = {}
        saveob["timestamp"] = create_timestamp()
        saveob["private"] = self.parent.sessions[certhash].private
        saveob["owner"] = True
        saveob["type"] = "img"
        saveob["size"] = len(_img2)
        saveob["hash"] = hashlib.sha256(_img2).hexdigest()
        
        sock, _cert, _hash = self.parent.sessions[certhash].request("send_img", "/{size}".format(size=len(_img2)))
        if sock is None and self.parent.sessions[certhash].private>0:
            logging.error("sending failed")
            return
        elif sock is None: # if not private
            self.parent.sessions[certhash].send("send_img", "/{size}".format(size=len(_img2)), _img2)
        else:
            sock.sendall(_img2)
            sock.close()
        self.parent.sessions[certhash].add(saveob)
        

    def gtk_node_iface(self, _name, certhash, _addressfunc, _traversefunc, window):
        builder = Gtk.Builder()
        builder.add_from_file(os.path.join(self.parent.proot, "chat.ui"))
        builder.connect_signals(self)
        self.parent.sessions[certhash].senslabel = builder.get_object("sensitivel")
        self.parent.sessions[certhash].__cache_size_gui = 0
        self.parent.sessions[certhash].__cache_private_plus = 0
        
        textsende = builder.get_object("textsende")
        textsende.connect("activate", self.gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
        sendchatb = builder.get_object("sendchatb")
        sendchatb.connect("clicked", self.gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
        sendfileb = builder.get_object("sendfileb")
        sendfileb.connect("clicked", self.gtk_send_file, _addressfunc, _traversefunc, window, certhash)
        sendimgb = builder.get_object("sendimgb")
        sendimgb.connect("clicked", self.gtk_send_img, _addressfunc, _traversefunc, window, certhash)
        privateselect = builder.get_object("privateselect")
        privateselect.connect("changed", self.update_private_select, certhash)
        
        #TODO: connect and autoscrolldown
        #sendchatb.connect("child_notify", gtk_scroll_down, builder.get_object("chatscroll"))
        
        clist = builder.get_object("chatlist")
        if self.parent.sessions[certhash].buffer_gui is None:
            self.parent.sessions[certhash].buffer_gui = Gio.ListStore()
            #init_async( certhash, _addressfunc)
            #Gdk.threads_add_idle(GLib.PRIORITY_LOW, self.init_async, certhash, _addressfunc, _traversefunc)
            threading.Thread(target=self.updateb, args=(certhash,), daemon=True).start()
            # broken so use own function to workaround
            #clist.bind_model(chatbuf[certhash], Gtk.ListBoxCreateWidgetFunc)

        clist.bind_model(self.parent.sessions[certhash].buffer_gui, myListBoxCreateWidgetFunc)
        
        builder.get_object("chatin").connect("destroy", self.parent.cleanup, certhash)
        
        self.parent.sessions[certhash].load()
        return builder.get_object("chatin")

    def update_private(self, certhash):
        Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, self.update_private_intern, certhash)

    def update_private_intern(self, certhash):
        
        sensitive = self.parent.sessions[certhash].num_sensitive()
        private = self.parent.sessions[certhash].num_private()
        if self.parent.sessions[certhash].private > 0:
            private_plus = private - self.parent.sessions[certhash].__cache_private_plus
        else:
            private_plus = 0
        self.parent.sessions[certhash].__cache_private_plus = private
        self.parent.sessions[certhash].senslabel.set_text("private: {}+({}), sensitive: {}".format(private, private_plus, sensitive))

    def updateb(self, certhash):
        Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, self.updateb_intern, certhash)
        self.updateb_add(certhash)
    
    def updateb_intern(self, certhash):
        self.parent.sessions[certhash].__cache_size_gui = 0
        self.parent.sessions[certhash].__cache_private_plus = 0
        self.parent.sessions[certhash].buffer_gui.remove_all()
    
    def updateb_add(self, certhash):
        self.update_private(certhash)
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
            while len(self.parent.sessions[certhash].buffer) > self.parent.sessions[certhash].__cache_size_gui:
                temp = self.parent.sessions[certhash].buffer[self.parent.sessions[certhash].__cache_size_gui]
                if temp["type"] == "text":
                    self.glist_add_certhash(certhash, self.gtk_create_textob, temp["owner"], temp["private"], parse_timestamp(temp["timestamp"]), temp["text"])
                elif temp["type"] == "img":
                    if temp["private"] == 0:
                        with open(os.path.join(self.parent.sessions[certhash].sessionpath,
                            "images", temp.get("hash")+".jpg"),"rb") as imgob:
                            img = imgob.read()
                    else:
                        img = temp["data"]
                    self.glist_add_certhash(certhash, self.gtk_create_imgob, temp["owner"], temp["private"], parse_timestamp(temp["timestamp"]), img)
                elif temp["type"] == "file":
                    self.glist_add_certhash(certhash, self.gtk_create_fileob, temp["owner"], temp["private"], parse_timestamp(temp["timestamp"]), temp.get("name"), temp.get("size"), self.parent.sessions[certhash].addressfunc, self.parent.sessions[certhash].traversefunc, certhash)
                self.parent.sessions[certhash].__cache_size_gui += 1
        return False

