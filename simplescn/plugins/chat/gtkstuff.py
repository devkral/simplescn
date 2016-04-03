

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
        self.parent.sessions[certhash].buffer.append(func(*args))

    def gtk_create_textob(self, _text, isowner, isprivate, timestamp):
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


    def gtk_create_imageob(self, _img, isowner, isprivate, timestamp):
        #timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
        # now set to scale down
        newimg = _img.scale_simple(100, 100, GdkPixbuf.InterpType.BILINEAR)
        newimg = Gtk.Image.new_from_pixbuf(newimg)
        newimg.set_can_focus(False)
        if isowner:
            newimg.set_halign(Gtk.Align.END)
            if isprivate:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
            else:
                newimg.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
        else:
            newimg.set_halign(Gtk.Align.START)
            if isprivate:
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


    def gtk_create_fileob(self, _addressfunc, _traversefunc, certhash, filename, size, isowner, isprivate, timestamp):
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

    def gtk_send_text(self, widget, _textwidget, _addressfunc, _traversefunc, certhash):
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
        _text = _textwidget.get_text()
        _timestamp = create_timestamp()
        with self.parent.sessions[certhash].lock:
            _textb = bytes(_text, "utf-8")
            if len(_textb) == 0:
                return True
            sock, _cert, _hash = self.parent.sessions[certhash].request("send_text", "/{size}".format(size=len(_textb)))
            if sock is None and self.parent.sessions[certhash].private:
                logging.error("request failed")
                return False
            elif sock is None:
                self.parent.sessions[certhash].send("send_text", "/{size}".format(size=len(_textb)), _textb)
                
            else:
                sock.sendall(_textb)
                sock.close()
            if self.parent.sessions[certhash].private == False:
                with open(os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                    wrio.write("ot:{timestamp}:{}\n".format(_text, timestamp=_timestamp))
            _textwidget.set_text("")
            self.glist_add_certhash(certhash, self.gtk_create_textob, _text, True, self.parent.sessions[certhash].private, parse_timestamp(_timestamp))
            #self.parent.chatbuf[certhash].append(self.gtk_create_textob(_text, True, self.parent.session[certhash].private, parse_timestamp(_timestamp)))

    def gtk_send_file(self, widget, _addressfunc, _traversefunc, window, certhash):
        with self.parent.chatlock[certhash]:
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
        shutil.copyfile(_filename, os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "tosend", _newname))
        
        with self.parent.chatlock[certhash]:
            if self.parent.chatlock[certhash].private == False:
                timestamp = create_timestamp()
                with open(os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                    wrio.write("of:{timestamp}:{},{}\n".format(_newname, _size, timestamp=timestamp))
            self.glist_add_certhash(certhash, self.gtk_create_fileob, _addressfunc, _traversefunc, certhash, _newname, _size, True, self.parent.chatlock[certhash].private, parse_timestamp(timestamp))
            #self.parent.chatbuf[certhash].append(self.gtk_create_fileob(_addressfunc, _traversefunc, certhash, _newname, _size, True, self.parent.session[certhash].private, parse_timestamp(timestamp)))
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
        sock, _cert, _hash = self.parent.sessions[certhash].request("send_img", "/{size}".format(size=len(_img2)))
        if sock is None and self.parent.sessions[certhash].private:
            logging.error("sending failed")
            return
        elif sock is None:
            self.parent.sessions[certhash].send("send_img", "/{size}".format(size=len(_img2)), _img2)
        else:
            sock.sendall(_img2)
        
        #sock.close()
        timest = create_timestamp()
        with self.parent.sessions[certhash].lock:
            if self.parent.sessions[certhash].private == False:
                _imgname = hashlib.sha256(_img2).hexdigest()+".jpg"
                with open(os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "images", _imgname), "wb") as imgo:
                    imgo.write(_img2)
                    
                with open(os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                    wrio.write("oi:{timestamp}:{}\n".format(_imgname, timestamp=timest))
            self.glist_add_certhash(certhash, self.gtk_create_imageob, newimg, True, self.parent.sessions[certhash].private, parse_timestamp(timest))
            #self.parent.chatbuf[certhash].append(self.gtk_create_imageob(newimg, True, self.parent.session[certhash].private, parse_timestamp(timest)))
            

    def gtk_node_iface(self, _name, certhash, _addressfunc, _traversefunc, window):
        builder = Gtk.Builder()
        builder.add_from_file(os.path.join(self.parent.proot, "chat.ui"))
        builder.connect_signals(self)
        
        textsende = builder.get_object("textsende")
        textsende.connect("activate", self.gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
        sendchatb = builder.get_object("sendchatb")
        sendchatb.connect("clicked", self.gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
        sendfileb = builder.get_object("sendfileb")
        sendfileb.connect("clicked", self.gtk_send_file, _addressfunc, _traversefunc, window, certhash)
        sendimgb = builder.get_object("sendimgb")
        sendimgb.connect("clicked", self.gtk_send_img, _addressfunc, _traversefunc, window, certhash)
        
        #TODO: connect and autoscrolldown
        #sendchatb.connect("child_notify", gtk_scroll_down, builder.get_object("chatscroll"))
        
        clist = builder.get_object("chatlist")
        if self.parent.sessions[certhash].buffer is None:
            self.parent.sessions[certhash].buffer = Gio.ListStore()
            #init_async( certhash, _addressfunc)
            #Gdk.threads_add_idle(GLib.PRIORITY_LOW, self.init_async, certhash, _addressfunc, _traversefunc)
            threading.Thread(target=self.init_async, args=(certhash,), daemon=True).start()
            # broken so use own function to workaround
            #clist.bind_model(chatbuf[certhash], Gtk.ListBoxCreateWidgetFunc)
        clist.bind_model(self.parent.sessions[certhash].buffer, myListBoxCreateWidgetFunc)
        
        builder.get_object("chatin").connect("destroy", self.parent.cleanup, certhash)
        return builder.get_object("chatin")

    def init_async(self, certhash):
        with self.parent.sessions[certhash].lock:
            self.parent.sessions[certhash].init_pathes()
            try:
                with open(os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash,"log.txt"), "r") as reio:
                    for line in reio.readlines():
                        if line[-1] == "\n":
                            line = line[:-1]
                        if line[-1] == "\r":
                            line = line[:-1]
                        _type, timestamp, _rest = line.split(":", 2)
                        if _type == "ot":
                            self.glist_add_certhash(certhash, self.gtk_create_textob, _rest, True, False, parse_timestamp(timestamp))
                            #self.parent.chatbuf[certhash].append(self.gtk_create_textob(_rest, True, False, parse_timestamp(timestamp)))
                        elif _type == "rt":
                            self.glist_add_certhash(certhash, self.gtk_create_textob, _rest, False, False, parse_timestamp(timestamp))
                            #self.parent.chatbuf[certhash].append(self.gtk_create_textob(_rest, False, False, parse_timestamp(timestamp)))
                        elif _type == "oi":
                            _imgpath = os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "images", _rest)
                            try:
                                if os.path.isfile(_imgpath):
                                    with open(_imgpath, "rb") as rob:
                                        newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                        newimg.write(rob.read())
                                        newimg.close()
                                        newimg = newimg.get_pixbuf()
                                        self.glist_add_certhash(certhash, self.gtk_create_imageob, newimg, True, False, parse_timestamp(timestamp))
                                        #self.parent.chatbuf[certhash].append(self.gtk_create_imageob(newimg, True, False, parse_timestamp(timestamp)))
                                else:
                                    logging.debug("path: {} does not exist anymore".format(_imgpath))
                            except Exception as e:
                                logging.error(e)
                        elif _type == "ri":
                            _imgpath = os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash, "images", _rest)
                            try:
                                if os.path.isfile(_imgpath):
                                    with open(_imgpath, "rb") as rob:
                                        newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                        newimg.write(rob.read())
                                        newimg.close()
                                        newimg = newimg.get_pixbuf()
                                        self.glist_add_certhash(certhash, self.gtk_create_imageob, newimg, False, False, parse_timestamp(timestamp))
                                        #self.parent.chatbuf[certhash].append(self.gtk_create_imageob(newimg, False, False, parse_timestamp(timestamp)))
                                else:
                                    logging.debug("path: {} does not exist anymore".format(_imgpath))
                            except Exception as e:
                                logging.error(e)
                        elif _type == "of":
                            _name, _size = _rest.rsplit(",", 1)
                            # autoclean
                            self.glist_add_certhash(certhash, self.gtk_create_fileob, self.parent.sessions[certhash].addressfunc, self.parent.sessions[certhash].traversefunc, certhash, _name, int(_size), True, False, parse_timestamp(timestamp))
                            #self.parent.chatbuf[certhash].append(self.gtk_create_fileob(_addressfunc, _traversefunc, certhash, _name, int(_size), True, False, parse_timestamp(timestamp)))
                        elif _type == "rf":
                            _name, _size = _rest.rsplit(",", 1)
                            self.glist_add_certhash(certhash, self.gtk_create_fileob, self.parent.sessions[certhash].addressfunc, self.parent.sessions[certhash].traversefunc, certhash, _name, int(_size), False, False, parse_timestamp(timestamp))
                            #self.parent.chatbuf[certhash].append(self.gtk_create_fileob(_addressfunc, _traversefunc, certhash, _name, int(_size), False, False, parse_timestamp(timestamp)))
                        
            except FileNotFoundError:
                pass
        

    def gtk_receive_text(self, certhash, _text, _private, timestamp):
        self.glist_add_certhash(certhash, self.gtk_create_textob, _text, False, _private, parse_timestamp(timestamp))
        return False # for not beeing read (threads_add_idle)


    def gtk_receive_img(self, certhash, img, private, timestamp):
        newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
        newimg.write(img)
        newimg.close()
        newimg = newimg.get_pixbuf()
        self.glist_add_certhash(certhash, self.gtk_create_imageob, newimg, False, private, parse_timestamp(timestamp))
        return False # for not beeing read (threads_add_idle)

    def gtk_receive_file(self, certhash, filename, size, private, timestamp):
        if certhash not in self.parent.chaturl:
            return
        self.glist_add_certhash(certhash, self.gtk_create_fileob, self.parent.chaturl[certhash][0], self.parent.chaturl[certhash][1], certhash, filename, size, False, private, parse_timestamp(timestamp))
        return False # for not beeing read (threads_add_idle)

