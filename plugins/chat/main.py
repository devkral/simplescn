

import sys
try:
    import gtkstuff
except ImportError as e:
    print(e)
    print(sys.path)
    print(__path__)
    gtkstuff = None
import datetime
import os.path
import hashlib
import shutil
from threading import Lock

###### used by pluginmanager ######

# defaults for config (needed)
config_defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": ["400", int, "max image size in KB"], "maxsizetext": ["4000", int, "max size text"]}

# interfaces, config, accessable resources (communication with main program), pluginpath, logger
# return None deactivates plugin
def init(interfaces, config, resources, proot, _logger):
    #global logger
    
    if "gtk" not in interfaces or gtkstuff is None:
        return None
    

    #logger = _logger
    #port_to_answer = resources("access")("show")[1]["port"]
    # assign port to answer
    #/{timestamp}
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return chat_plugin(interfaces, config, resources, proot, _logger)

###### used by pluginmanager end ######

def create_timestamp():
    return datetime.datetime.today().strftime("%Y_%m_%d_%H_%M_%S")

def parse_timestamp(_inp):
    return datetime.datetime.strptime(_inp, "%Y_%m_%d_%H_%M_%S")

def unparse_timestamp(_inp):
    return _inp.strftime(_inp, "%Y_%m_%d_%H_%M_%S")

class chat_plugin(object):
    lname = {"*": "Chat"}

    chatbuf = {}
    chatlock = {}
    chaturl = {}
    private_state = {}
    openforeign = 0
    reqstring = None
    gui = None

    gui_node_actions = None
    
    def __init__(self, interfaces, config, resources, proot, logger):
        self.interfaces, self.config, self.resources, self.proot, self.logger = interfaces, config, resources, proot, logger
        self.reqstring = "{action}/{privstate}/%s{other}" % resources("access")("show")[1]["port"]
        self.gui_node_actions = [
{"text":"private", "action": self.toggle_private, \
"interfaces": ["gtk",], "description": "Toggle private chat", "state": False},
{"text":"Delete log", "action": self.delete_log, \
"interfaces": ["gtk",], "description": "Delete the chat log"}
]
        self.gui = gtkstuff.gtkstuff(self)

    def cleanup(self, widget, certhash):
        del self.chaturl[certhash]
        #port_to_answer = None


    def init_pathes(self, _hash):
        os.makedirs(os.path.join(os.path.expanduser(self.config.get("chatdir")), _hash), 0o770, exist_ok=True)
        os.makedirs(os.path.join(os.path.expanduser(self.config.get("chatdir")), _hash, "images"), 0o770, exist_ok=True)
        os.makedirs(os.path.join(os.path.expanduser(self.config.get("chatdir")), _hash, "tosend"), 0o770, exist_ok=True)


    def request(self, url, certhash, action, arguments, traverseserveraddr=None): #, timestamp=create_timestamp()): #, _traversefunc()
        if url is None:
            self.logger().error("No address")
            return None
        if self.private_state.get(certhash, False):
            privstate = "private"
        else:
            privstate = "public"
        #sock, _cert, _hash = 
        #, timestamp=timestamp
        return self.resources("plugin")(url, "chat", self.reqstring.format(action=action, privstate=privstate, other=arguments), forcehash=certhash, traverseserveraddr=traverseserveraddr)




    def delete_log(self, gui, _addressfunc, window, certhash, dheader):
        if certhash not in self.chatlock:
            return
        with self.chatlock[certhash]:
            try:
                shutil.rmtree(os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash))
                #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
            except FileNotFoundError:
                pass
            self.chatbuf[certhash].remove_all()
        

    def toggle_private(self, gui, _addressfunc, window, certhash, state, dheader):
        if state:
            self.private_state[certhash] = True
        else:
            self.private_state[certhash] = False

    def gui_node_iface(self, gui, _name, certhash, _addressfunc, _traversefunc, window):
        if certhash not in self.chatlock:
            self.chatlock[certhash] = Lock()
        if certhash not in self.chaturl:
            self.chaturl[certhash] = (_addressfunc, _traversefunc)
        if gui != "gtk":
            return None
        return self.gui.gtk_node_iface(_name, certhash, _addressfunc, _traversefunc, window)

    def receive(self, action, _socket, _cert, certhash):
        splitted = action.split("/", 3)
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
                self.logger().error("Invalid filename")
                return
            _path = os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "tosend", name)
            if os.path.isfile(_path):
                with open(_path, "rb") as rbfile: 
                    _socket.sendfile(rbfile, int(pos))
            return
    
        #if certhash not in self.chatlock:
        #    if resources("access")("getlocal", hash=certhash)[0] == False:
        #        return
        #    self.resources("open_node")("{}-{}".format(_socket.getsockname()[0], answerport), page="chat", forcehash=certhash)
    
        if certhash not in self.chatlock:
            # if still not existent
            return
        self.init_pathes(certhash)
    
        with self.chatlock[certhash]:
            if action == "send_text":
                _size = int(_rest)
                if _size > self.config.get("maxsizetext"):
                    return
                countread = 0
                _textb = b""
                while countread <= _size-1024:
                    _data = _socket.recv(1024)
                    _textb += _data
                    countread += len(_data)
                _textb += _socket.recv(_size-countread)
                _text = str(_textb, "utf-8")
                if private == False:
                    with open (os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                        logob.write("rt:{timestamp}:{text}\n".format(timestamp=timestamp, text=_text.replace("\n", "\\n").replace("\r", "\\r")))
                        # improve
                if "gtk" in self.interfaces and gtkstuff is not None:
                    gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, self.gui.gtk_receive_text, certhash, _text, private, timestamp)
            elif action == "send_img":
                _size = int(_rest)
                if _size > self.config.get("maxsizeimg")*1024:
                    _socket.close()
                    return
                countread = 0
                _img = b""
                while countread <= _size-1024:
                    _data = _socket.recv(1024)
                    _img += _data
                    countread += len(_data)
                _img += _socket.recv(_size-countread)
                
                
                if private == False:
                    _imgname = hashlib.sha256(_img).hexdigest()+".jpg"
                    with open (os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "images", _imgname), "wb") as imgob:
                        imgob.write(_img)
                    with open (os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                        logob.write("ri:{timestamp}:{name}\n".format(timestamp=timestamp, name=_imgname))
            
                if "gtk" in self.interfaces and gtkstuff is not None:
                    gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, self.gui.gtk_receive_img, certhash, _img, private, timestamp)
            elif action == "send_file":
                _name, _size = _rest.split("/", 1)
                if private == False:
                    with open (os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                        logob.write("rf:{timestamp}:{name},{size}\n".format(name=_name, size=_size, timestamp=timestamp))
                if "gtk" in self.interfaces and gtkstuff is not None:
                    gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, self.gui.gtk_receive_file, certhash, _name, int(_size), private, timestamp)
    
    ## executed when redirected, return False, when redirect should not be executed
    # def rreceive(self, action, _socket, _cert, certhash):
    #     pass
    ### server:
    # def sreceive(self, action, _socket, _cert, certhash):
    #     pass
