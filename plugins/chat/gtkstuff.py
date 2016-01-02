

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango, Gio, GLib, GdkPixbuf

import __init__
import os
import hashlib
import shutil


def myListBoxCreateWidgetFunc(item, **userdata):
    return item


def gtk_create_textob(_text, isowner, isprivate, timestamp):
    timest = timestamp.strftime("%Y.%m.%d %H:%M:%S")
    ret = Gtk.Label(_text, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, selectable=True)
    
    if isowner:
        ret.set_halign(Gtk.Align.END)
        ret.set_justify(Gtk.Justification.RIGHT)
        if isprivate:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
        else:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
            
    else:
        ret.set_halign(Gtk.Align.START)
        ret.set_justify(Gtk.Justification.LEFT)
        if isprivate:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=0.9))
        else:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=0.7))
    return ret


def gtk_create_imageob(_img, isowner, isprivate, timestamp):
    timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
    # now set to scale down
    newimg = _img.scale_simple(100, 100, GdkPixbuf.InterpType.BILINEAR)
    newimg = Gtk.Image.new_from_pixbuf(newimg)
    newimg.set_can_focus(False)
    if isowner:
        newimg.set_halign(Gtk.Align.END)
        if isprivate:
            newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
        else:
            newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
    else:
        newimg.set_halign(Gtk.Align.START)
        if isprivate:
            newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=0.9))
        else:
            newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=0.7))
    
    return newimg

def gtk_download(widget, _addressfunc, _traversefunc, certhash, filename, size, pos=0):
    _filech = Gtk.FileChooserDialog(title="Save to file", parent=widget.get_toplevel(), select_multiple=False, action=Gtk.FileChooserAction.SAVE, buttons=("Save", 10, "Cancel", 20))
    #filech.set_filename(os.path.join filename)
    retrun = _filech.run()
    if retrun != 10:
        _filech.destroy()
        return
    _file2 = _filech.get_filename()
    _filech.destroy()
    _socket, _cert, _hash = __init__.request(_addressfunc(), certhash, "fetch_file", "/{filename}/{pos}".format(filename=filename, pos=pos), _traversefunc())
    if _socket is None:
        __init__.logger().error("fetching file failed")
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


def gtk_create_fileob(_addressfunc, _traversefunc, certhash, filename, size, isowner, isprivate, timestamp):
    timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
    ret = Gtk.Grid()
    if isowner:
        ret.attach_next_to(Gtk.Label("Offer File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
        ret.set_halign(Gtk.Align.END)
    else:
        ret.attach_next_to(Gtk.Label("File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
        downbut = Gtk.Button("Download ({} KB)".format(size // 1024))
        downbut.connect("clicked", gtk_download, _addressfunc, _traversefunc, certhash, filename, size)
        ret.attach_next_to(downbut, None, Gtk.PositionType.RIGHT, 1, 1)
        ret.set_halign(Gtk.Align.START)
    ret.show_all()
    return ret
    
def gtk_scroll_down(widget, child_prop, scroller):
    if isinstance(widget, Gtk.ListBox): # and scroller.get_value()<10:
        scroller.set_value(100)




def gtk_send_text(widget, _textwidget, _addressfunc, _traversefunc, certhash):
    with __init__.chatlock[certhash]:
        __init__.init_pathes(certhash)
    _text = _textwidget.get_text()
    _timestamp = __init__.create_timestamp()
    with __init__.chatlock[certhash]:
        _textb = bytes(_text, "utf-8")
        if len(_textb) == 0:
            return True
        sock, _cert, _hash = __init__.request(_addressfunc(), certhash, "send_text", "/{size}".format(size=len(_textb)), traverseserveraddr=_traversefunc())
        if sock is None:
            __init__.logger().error("request failed")
            return False
        if __init__.private_state.get(certhash, False) == False:
            with open(os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                wrio.write("ot:{timestamp}:{}\n".format(_text, timestamp=_timestamp))
        sock.sendall(_textb)
        sock.close()
        _textwidget.set_text("")
        __init__.chatbuf[certhash].append(gtk_create_textob(_text, True, __init__.private_state.get(certhash, False), __init__.parse_timestamp(_timestamp)))

def gtk_send_file(widget, _addressfunc, _traversefunc, window, certhash):
    with __init__.chatlock[certhash]:
        __init__.init_pathes(certhash)
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
    shutil.copyfile(_filename, os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "tosend", _newname))
    
    with __init__.chatlock[certhash]:
        if __init__.private_state.get(certhash, False) == False:
            timestamp = __init__.create_timestamp()
            with open(os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                wrio.write("of:{timestamp}:{},{}\n".format(_newname, _size, timestamp=timestamp))
        __init__.chatbuf[certhash].append(gtk_create_fileob(_addressfunc, _traversefunc, certhash, _newname, _size, True, __init__.private_state.get(certhash, False), __init__.parse_timestamp(timestamp)))
        sock, _cert, _hash = __init__.request(_addressfunc(), certhash, "send_file","/{name}/{size}".format(name=_newname, size=_size), _traversefunc())
        if sock is None:
            __init__.logger().error("Cannot connect/other error")
            return

def gtk_send_img(widget, _addressfunc, _traversefunc, window, certhash):
    with __init__.chatlock[certhash]:
        __init__.init_pathes(certhash)
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
    if len(_img2) > __init__.config.get("maxsizeimg")*1024:
        __init__.logger().info("Image too big")
        return
    sock, _cert, _hash = __init__.request(_addressfunc(), certhash, "send_img", "/{size}".format(size=len(_img2)), _traversefunc())
    if sock is None:
        __init__.logger().error("sending failed")
        return
    sock.sendall(_img2)
    
    #sock.close()
    timest = __init__.create_timestamp()
    with __init__.chatlock[certhash]:
        if __init__.private_state.get(certhash, False) == False:
            _imgname = hashlib.sha256(_img2).hexdigest()+".jpg"
            with open(os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "images", _imgname), "wb") as imgo:
                imgo.write(_img2)
                
            with open(os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                wrio.write("oi:{timestamp}:{}\n".format(_imgname, timestamp=timest))
        __init__.chatbuf[certhash].append(gtk_create_imageob(newimg, True, __init__.private_state.get(certhash, False), __init__.parse_timestamp(timest)))
        

def gtk_node_iface(_name, certhash, _addressfunc, _traversefunc, window):
    builder = Gtk.Builder()
    __init__.private_state[certhash] = False
    builder.add_from_file(os.path.join(__init__.proot, "chat.ui"))
    builder.connect_signals(__init__.gtk)
    

    textsende = builder.get_object("textsende")
    textsende.connect("activate", gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
    sendchatb = builder.get_object("sendchatb")
    sendchatb.connect("clicked", gtk_send_text, textsende, _addressfunc, _traversefunc, certhash)
    sendfileb = builder.get_object("sendfileb")
    sendfileb.connect("clicked", gtk_send_file, _addressfunc, _traversefunc, window, certhash)
    sendimgb = builder.get_object("sendimgb")
    sendimgb.connect("clicked", gtk_send_img, _addressfunc, _traversefunc, window, certhash)
    
    #TODO: connect and autoscrolldown
    #sendchatb.connect("child_notify", gtk_scroll_down, builder.get_object("chatscroll"))
    
    clist = builder.get_object("chatlist")
    if certhash not in __init__.chatbuf:
        __init__.chatbuf[certhash] = Gio.ListStore()
        #init_async( certhash, _addressfunc)
        Gdk.threads_add_idle(GLib.PRIORITY_LOW, init_async, certhash, _addressfunc, _traversefunc)
    
        # broken so use own function to workaround
        #clist.bind_model(chatbuf[certhash], Gtk.ListBoxCreateWidgetFunc)
    clist.bind_model(__init__.chatbuf[certhash], myListBoxCreateWidgetFunc)
    
    builder.get_object("chatin").connect("destroy", __init__.cleanup, certhash)
    return builder.get_object("chatin")

def init_async(certhash, _addressfunc, _traversefunc):
    with __init__.chatlock[certhash]:
        __init__.init_pathes(certhash)
        try:
            with open(os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash,"log.txt"), "r") as reio:
                for line in reio.readlines():
                    if line[-1] == "\n":
                        line = line[:-1]
                    if line[-1] == "\r":
                        line = line[:-1]
                    _type, timestamp, _rest = line.split(":", 2)
                    if _type == "ot":
                        __init__.chatbuf[certhash].append(gtk_create_textob(_rest, True, False, __init__.parse_timestamp(timestamp)))
                    elif _type == "rt":
                        __init__.chatbuf[certhash].append(gtk_create_textob(_rest, False, False, __init__.parse_timestamp(timestamp)))
                    elif _type == "oi":
                        _imgpath = os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "images", _rest)
                        try:
                            if os.path.isfile(_imgpath):
                                with open(_imgpath, "rb") as rob:
                                    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                    newimg.write(rob.read())
                                    newimg.close()
                                    newimg = newimg.get_pixbuf()
                                    chatbuf[certhash].append(gtk_create_imageob(newimg, True, False, __init__.parse_timestamp(timestamp)))
                            else:
                                __init__.logger().debug("path: {} does not exist anymore".format(_imgpath))
                        except Exception as e:
                            __init__.logger().error(e)
                    elif _type == "ri":
                        _imgpath = os.path.join(os.path.expanduser(__init__.config.get("chatdir")), certhash, "images", _rest)
                        try:
                            if os.path.isfile(_imgpath):
                                with open(_imgpath, "rb") as rob:
                                    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                    newimg.write(rob.read())
                                    newimg.close()
                                    newimg = newimg.get_pixbuf()
                                    __init__.chatbuf[certhash].append(gtk_create_imageob(newimg, False, False, __init__.parse_timestamp(timestamp)))
                            else:
                                __init__.logger().debug("path: {} does not exist anymore".format(_imgpath))
                        except Exception as e:
                            __init__.logger().error(e)
                    elif _type == "of":
                        _name, _size = _rest.rsplit(",", 1)
                        # autoclean
                        __init__.chatbuf[certhash].append(gtk_create_fileob(_addressfunc, _traversefunc, certhash, _name, int(_size), True, False, __init__.parse_timestamp(timestamp)))
                    elif _type == "rf":
                        _name, _size = _rest.rsplit(",", 1)
                        __init__.chatbuf[certhash].append(gtk_create_fileob(_addressfunc, _traversefunc, certhash, _name, int(_size), False, False, __init__.parse_timestamp(timestamp)))
                    
        except FileNotFoundError:
            pass
    

def gtk_receive_text(certhash, _text, _private, timestamp):
    __init__.chatbuf[certhash].append(gtk_create_textob(_text, False, _private, __init__.parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)


def gtk_receive_img(certhash, img, private, timestamp):
    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
    newimg.write(img)
    newimg.close()
    newimg = newimg.get_pixbuf()
    __init__.chatbuf[certhash].append(gtk_create_imageob(newimg, False, private, __init__.parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)

def gtk_receive_file(certhash, filename, size, private, timestamp):
    if certhash not in __init__.chaturl:
        return
    __init__.chatbuf[certhash].append(gtk_create_fileob(__init__.chaturl[certhash][0], __init__.chaturl[certhash][1], certhash, filename, size, False, private, __init__.parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)

