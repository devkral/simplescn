
from threading import Lock
#import os
#import sys
import datetime
import os.path
import hashlib
import shutil
try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk, Pango, Gio, GLib,  GdkPixbuf
except ImportError:
    gtk_chat = None

###### created by pluginmanager ######
# specifies the interfaces
interfaces = None

# configmanager (see common)
config = None

# resources which can be accessed
resources = None

# plugin path
proot = None

# this module
module = None

###### created by pluginmanager end ######

lname = {"*": "Chat"}


# defaults for config (needed)
defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": ["400", int, "max image size in KB"],"maxsizetext": ["4000", int, "max size text"]}

chatbuf = {}
chatlock = {}
private_state = {}
openforeign = 0
#port_to_answer = None

reqstring = None

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    global reqstring
    if "gtk" not in interfaces:
        return False
    #port_to_answer = resources("access")("show")[1]["port"]
    # assign port to answer
    #/{timestamp}
    reqstring = "{action}/{privstate}/%s{other}" % resources("access")("show")[1]["port"]
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return True


def init_pathes(_hash):
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images"), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "tosend"), 0o770, exist_ok=True)


def request(url, certhash, action, arguments): #, timestamp=create_timestamp()):
    if private_state.get(certhash, False):
        privstate = "private"
    else:
        privstate = "public"
    #sock, _cert, _hash = 
    #, timestamp=timestamp
    return resources("plugin")(url, "chat", reqstring.format(action=action, privstate=privstate, other=arguments), forcehash=certhash)


def create_timestamp():
    return datetime.datetime.today().strftime("%Y_%m_%d_%H_%M_%S")

def parse_timestamp(_inp):
    return datetime.datetime.strptime(_inp, "%Y_%m_%d_%H_%M_%S")

def unparse_timestamp(_inp):
    return inp.strftime(_inp, "%Y_%m_%d_%H_%M_%S")


def gtk_create_textob(_text, isowner, isprivate, timestamp):
    timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
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

def gtk_download(widget, url, certhash, filename, size, pos=0):
    _filech = Gtk.FileChooserDialog(title="Save to file", parent=widget.get_toplevel(), select_multiple=False, action=Gtk.FileChooserAction.SAVE, buttons=("Save",10, "Cancel",20))
    #filech.set_filename(os.path.join filename)
    retrun = _filech.run()
    if retrun != 10:
        _filech.destroy()
        return
    _file2 = _filech.get_filename()
    _filech.destroy()
    _socket, _cert, _hash = request(url, certhash, "fetch_file", "/{filename}/{pos}".format(filename=filename, pos=pos))
    if _socket is None:
        logger().error("fetching file failed")
        return
    
    if os.path.exists(_file2) and pos > 0:
        _omode = "r+b"
    else:
        _omode = "wb"
    with open(_file2, _omode) as wrio:
        if _omode == "r+b":
            wrio.seek(pos)
        while pos<size-1024:
            wrio.write(_socket.recv(1024))
            pos += 1024
        wrio.write(_socket.recv(size-pos))


def gtk_create_fileob(url, certhash, filename, size, isowner, isprivate, timestamp):
    timest = timestamp.strftime("%Y.%m.%d %H:%M%S")
    ret = Gtk.Grid()
    if isowner:
        ret.attach_next_to(Gtk.Label("Offer File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
        ret.set_halign(Gtk.Align.END)
    else:
        ret.attach_next_to(Gtk.Label("File: {}".format(filename)), None, Gtk.PositionType.RIGHT, 1, 1)
        downbut = Gtk.Button("Download ({} KB)".format(size//1024))
        downbut.connect("clicked", gtk_download, url, certhash, filename, size)
        ret.attach_next_to(downbut, None, Gtk.PositionType.RIGHT, 1, 1)
        ret.set_halign(Gtk.Align.START)
    ret.show_all()
    return ret
    
def gtk_scroll_down(widget, child_prop, scroller):
    if isinstance(widget, Gtk.ListBox): # and scroller.get_value()<10:
        scroller.set_value(100)


def gtk_send_text(widget, _textwidget, _address, certhash):
    _text = _textwidget.get_text()
    _timestamp = create_timestamp()
    with chatlock[certhash]:
        send_text(_address, certhash, _text, _timestamp)
        _textwidget.set_text("")
        #_oldlineno = chatbuf[certhash].get_line_count()
        #chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text+"\n")
        #_newiter = chatbuf[certhash].get_end_iter()
        chatbuf[certhash].append(gtk_create_textob(_text, True, private_state.get(certhash, False), parse_timestamp(_timestamp)))

def gtk_send_file(widget, url, window, certhash):
    init_pathes(certhash)
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
    shutil.copyfile(_filename, os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", _newname))
    
    with chatlock[certhash]:
        if private_state.get(certhash, False) == False:
            timestamp = create_timestamp()
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                wrio.write("of:{timestamp}:{},{}\n".format(_newname, _size, timestamp=timestamp))
        chatbuf[certhash].append(gtk_create_fileob(url, certhash, _newname, _size, True, private_state.get(certhash, False), parse_timestamp(timestamp)))
        sock, _cert, _hash = request(url, certhash, "send_file","/{name}/{size}".format(name=_newname, size=_size))
        if sock is None:
            logger().error("Cannot connect/other error")
            return
        #sock.close()
    
    #if private_state[certhash] != "private":
    #    with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "a") as wrio:
    #        wrio.write("o:"+_text+"\n");
    #sock.sendfile(_textb)
    #sock.close()
    #return "Hello actions, return: "+url

def gtk_send_img(widget, url, window, certhash):
    init_pathes(certhash)
    _filech = Gtk.FileChooserDialog(title="Select image", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("Open",10, "Cancel",20))
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
    if len(_img2) > config.get("maxsizeimg")*1024:
        logger().info("Image too big")
        return
    sock, _cert, _hash = request(url, certhash, "send_img", "/{size}".format(size=len(_img2)))
    sock.sendall(_img2)
    
    #sock.close()
    with chatlock[certhash]:
        if private_state.get(certhash, False) == False:
            _imgname = hashlib.sha256(_img2).hexdigest()+".jpg"
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _imgname), "wb") as imgo:
                imgo.write(_img2)
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
                wrio.write("oi:{timestamp}:{}\n".format(_imgname,timestamp=create_timestamp()))
        chatbuf[certhash].append(gtk_create_imageob(newimg, True, private_state.get(certhash, False), parse_timestamp(create_timestamp())))
     
def delete_log(gui, url, window, certhash, dheader):
    if certhash not in chatlock:
        return
    with chatlock[certhash]:
        try:
            shutil.rmtree(os.path.join(os.path.expanduser(config.get("chatdir")), certhash))
            #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
        except FileNotFoundError:
            pass
        chatbuf[certhash].remove_all()
        
    #return "Hello actions, return: "+url

def toggle_private(gui, url, window, certhash, state, dheader):
    if state:
        private_state[certhash] = True
    else:
        private_state[certhash] = False

    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
#cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
#cmd_node_alias_actions={"Aktion": "foo-action"}

#{"text": "Send file", "action": send_file_gui, \
#"interfaces": ["gtk",], "description": "Send a file"},
# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[
{"text":"private", "action": toggle_private, \
"interfaces": ["gtk",], "description": "Toggle private chat", "state": False},
{"text":"Delete log", "action": delete_log, \
"interfaces": ["gtk",], "description": "Delete the chat log"}
]

# iterable, for server actions, just shows up in gui, do localization in plugin
#gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]



#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

def send_text(url, certhash, _text, _timestamp):
    init_pathes(certhash)
    _textb = bytes(_text, "utf-8")
    if len(_textb) == 0:
        return True
    sock, _cert, _hash = request(url, certhash, "send_text", "/{size}".format(size=len(_textb)))
    if sock is None:
        logger().error("request failed")
        return False
    if private_state.get(certhash, False) == False:
        with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
            wrio.write("ot:{timestamp}:{}\n".format(_text, timestamp=_timestamp))
    sock.sendall(_textb)
    sock.close()
    return True

def myListBoxCreateWidgetFunc(item, **userdata):
    return item
    
def gui_node_iface(gui, _name, certhash, _address, window):
    if certhash not in chatlock:
        chatlock[certhash] = Lock()
    if gui != "gtk":
        return None
    
    if certhash not in chatbuf:
        chatbuf[certhash] = Gio.ListStore()
        try:
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash,"log.txt"), "r") as reio:
                for line in reio.readlines():
                    if line[-1] == "\n":
                        line = line[:-1]
                    if line[-1] == "\r":
                        line = line[:-1]
                    _type, timestamp, _rest = line.split(":", 2)
                    if _type == "ot":
                        chatbuf[certhash].append(gtk_create_textob(_rest, True, False, parse_timestamp(timestamp)))
                    elif _type == "rt":
                        chatbuf[certhash].append(gtk_create_textob(_rest, False, False, parse_timestamp(timestamp)))
                    elif _type == "oi":
                        _imgpath = os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _rest)
                        try:
                            if os.path.isfile(_imgpath):
                                with open(_imgpath, "rb") as rob:
                                    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                    newimg.write(rob.read())
                                    newimg.close()
                                    newimg = newimg.get_pixbuf()
                                    chatbuf[certhash].append(gtk_create_imageob(newimg, True, False, parse_timestamp(timestamp)))
                            else:
                                logger().debug("path: {} does not exist anymore".format(_imgpath))
                        except Exception as e:
                            logger().error(e)
                    elif _type == "ri":
                        _imgpath = os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _rest)
                        try:
                            if os.path.isfile(_imgpath):
                                with open(_imgpath, "rb") as rob:
                                    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
                                    newimg.write(rob.read())
                                    newimg.close()
                                    newimg = newimg.get_pixbuf()
                                    chatbuf[certhash].append(gtk_create_imageob(newimg, False, False, parse_timestamp(timestamp)))
                            else:
                                logger().debug("path: {} does not exist anymore".format(_imgpath))
                        except Exception as e:
                            logger().error(e)
                    elif _type == "of":
                        _name, _size = _rest.rsplit(",", 1)
                        # autoclean
                        chatbuf[certhash].append(gtk_create_fileob(_address, certhash, _name, int(_size), True, False, parse_timestamp(timestamp)))
                    elif _type == "rf":
                        _name, _size = _rest.rsplit(",", 1)
                        chatbuf[certhash].append(gtk_create_fileob(_address, certhash, _name, int(_size), False, False, parse_timestamp(timestamp)))
                    
        except FileNotFoundError:
            pass
    
    private_state[certhash] = False
    builder = Gtk.Builder()
    builder.add_from_file(os.path.join(proot, "chat.ui"))
    builder.connect_signals(module)
    textsende = builder.get_object("textsende")
    textsende.connect("activate", gtk_send_text, textsende, _address, certhash)
    sendchatb = builder.get_object("sendchatb")
    sendchatb.connect("clicked", gtk_send_text, textsende, _address, certhash)
    sendfileb = builder.get_object("sendfileb")
    sendfileb.connect("clicked", gtk_send_file, _address, window, certhash)
    sendimgb = builder.get_object("sendimgb")
    sendimgb.connect("clicked", gtk_send_img, _address, window, certhash)
    
    #TODO: connect and autoscrolldown
    #sendchatb.connect("child_notify", gtk_scroll_down, builder.get_object("chatscroll"))
    clist = builder.get_object("chatlist")
    clist.bind_model(chatbuf[certhash], myListBoxCreateWidgetFunc)
    #clist.bind_model(chatbuf[certhash], Gtk.ListBoxCreateWidgetFunc)
    # broken so use own function to workaround
    return builder.get_object("chatin")



def gtk_receive_text(certhash, _text, _private, timestamp):
    chatbuf[certhash].append(gtk_create_textob(_text, False, _private, parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)


def gtk_receive_img(certhash, img, private, timestamp):
    newimg = GdkPixbuf.PixbufLoader.new_with_mime_type("image/jpeg")
    newimg.write(img)
    newimg.close()
    newimg = newimg.get_pixbuf()
    chatbuf[certhash].append(gtk_create_imageob(newimg, False, private, parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)

def gtk_receive_file(certhash, url, filename, size, private, timestamp):
    chatbuf[certhash].append(gtk_create_fileob(url, certhash, filename, size, False, private, parse_timestamp(timestamp)))
    return False # for not beeing readded (threads_add_idle)

### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/",3)
    if len(splitted) != 4:
        return
    action, private, answerport, _rest = splitted
    timestamp = create_timestamp()
    if private == "private":
        private = True
    else:
        private = False
    
    if action == "fetch_file":
        name, pos = _rest.split("/", 1)
        if "/" in name or "\\" in name or name[0] == ".":
            logger().error("Invalid filename")
            return
        _path = os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", name)
        if os.path.isfile(_path):
            with open(_path, "rb") as rbfile: 
                _socket.sendfile(rbfile, int(pos))
        return
        
    if certhash not in chatlock:
        if resources("access")("getlocal", hash=certhash)[0] == False:
            return
        resources("open_node")("{}-{}".format(_socket.getsockname()[0], answerport), page="chat")
    
        if certhash not in chatlock:
            # if still not existent
            return
    init_pathes(certhash)
    
    with chatlock[certhash]:
        if action == "send_text":
            _size = int(_rest)
            if _size > config.get("maxsizetext"):
                return
            _text = str(_socket.read(_size), "utf-8")
            if private == False:
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rt:{timestamp}:{text}\n".format(timestamp=timestamp, text=_text.replace("\n", "\\n").replace("\r", "\\r")))
                    # improve
                
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_text, certhash, _text, private, timestamp)
        elif action == "send_img":
            _size = int(_rest)
            if _size > config.get("maxsizeimg")*1024:
                sock.close()
                return
            countread = 0
            _img = b""
            while countread <= _size-1024:
                _img += _socket.recv(1024)
                countread += 1024
            _img += _socket.recv(_size-countread)
            
            
            if private == False:
                _imgname = hashlib.sha256(_img).hexdigest()+".jpg"
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _imgname), "wb") as imgob:
                    imgob.write(_img)
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("ri:{timestamp}:{name}\n".format(timestamp=timestamp, name=_imgname))
            
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_img, certhash, _img, private, timestamp)
        elif action == "send_file":
            _name, _size = _rest.split("/", 1)
            if private == False:
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rf:{timestamp}:{name},{size}\n".format(name=_name, size=_size, timestamp=timestamp))
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_file, certhash, "{}-{}".format(_socket.getsockname()[0], answerport), _name, int(_size), private, timestamp)
            
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
