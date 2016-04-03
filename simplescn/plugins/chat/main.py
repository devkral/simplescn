

#import sys
try:
    from . import gtkstuff
except ImportError as e:
    print(e)
    gtkstuff = None
import datetime
import os.path
import hashlib
import shutil
import time
import logging
from threading import RLock, Thread

###### used by pluginmanager ######

# defaults for config (needed)
config_defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": ["4000", int, "max image size in KB"], "maxsizetext": ["4000", int, "max size text in B"]}

# interfaces, config, accessable resources (communication with main program), pluginpath, logger
# return None deactivates plugin
def init(interfaces, config, resources, proot):
    #global logger
    if "gtk" not in interfaces or gtkstuff is None:
        return None

    #logger = _logger
    #port_to_answer = resources("access")("show")[1]["port"]
    # assign port to answer
    #/{timestamp}
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return chat_plugin(interfaces, config, resources, proot)

###### used by pluginmanager end ######

def create_timestamp():
    return datetime.datetime.today().strftime("%Y_%m_%d_%H_%M_%S")

def parse_timestamp(_inp):
    return datetime.datetime.strptime(_inp, "%Y_%m_%d_%H_%M_%S")

def unparse_timestamp(_inp):
    return _inp.strftime(_inp, "%Y_%m_%d_%H_%M_%S")

class hash_session(object):
    parent = None
    certhash = None
    buffer = None
    lock = None
    private = None
    addressfunc = None
    traversefunc = None
    window = None
    sessionpath = None
    outcounter = None
    _thread = None
    guitype = None
    gui = None
    name = None
    
    def __init__(self, guitype, parent,  _name, certhash, _addressfunc, _traversefunc, window):
        self.certhash = certhash
        self.parent = parent
        self.addressfunc = _addressfunc
        self.traversefunc = _traversefunc
        self.window = window
        self.lock = RLock()
        self.private = False
        self.guitype = guitype
        self.name = _name
        self.sessionpath = os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash)
        self.init_pathes()

        self._thread = Thread(target=self.sendthread, daemon=True)
        self._thread.start()
    
    def init_gui(self):
        if self.guitype != "gtk":
            return None
        return self.parent.gui.gtk_node_iface(self.name, self.certhash, self.addressfunc, self.traversefunc, self.window)

    def init_pathes(self):
        os.makedirs(self.sessionpath, 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "images"), 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "tosend"), 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "out"), 0o770, exist_ok=True)
        self.outcounter = len(os.listdir(os.path.join(self.sessionpath, "out")))//2

    def request(self, action, arguments): #, timestamp=create_timestamp()): #, _traversefunc()
        url = self.addressfunc()
        if url is None:
            logging.error("No address")
            return None
        if self.private:
            privstate = "private"
        else:
            privstate = "public"
        #sock, _cert, _hash = 
        #, timestamp=timestamp
        return self.parent.resources("plugin")(url, "chat", self.parent.reqstring.format(action=action, privstate=privstate, other=arguments), forcehash=self.certhash, traverseserveraddr=self.traversefunc())

    def sendthread(self):
        while True: 
            if self.addressfunc() is not None:
                for elem in sorted(os.listdir(os.path.join(self.sessionpath, "out"))):
                    num, _type = elem.split("_", 1)
                    if _type != "args":
                        continue
                    with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_args", "r") as readob:
                        if not os.path.exists(os.path.join(self.sessionpath, "out", num+"_file")):
                            continue
                        action, parameters = readob.read().split("/", 1)
                        with self.lock:
                            _socket, _cert, _hash = self.request(action, parameters)
                            if _socket:
                                with open(os.path.join(self.sessionpath, "out", num+"_file"), "rb") as readob:
                                    _socket.sendfile(readob)
                                    os.remove(os.path.join(self.sessionpath, "out", num+"_file"))
                                    os.remove(os.path.join(self.sessionpath, "out", num+"_args"))
                with self.lock:
                    self.outcounter = len(os.listdir(os.path.join(self.sessionpath, "out")))//2
            time.sleep(5)

    # send when connection is available
    def send(self, action, arguments, _ob):
        with self.lock:
            self.init_pathes()
            with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_args", "w") as writeob:
                writeob.write(action+"/"+arguments)
            with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_file", "wb") as writeob:
                writeob.write(_ob)
            self.outcounter += 1

class chat_plugin(object):
    lname = {"*": "Chat"}

    sessions = None
    openforeign = 0
    reqstring = None
    gui = None

    gui_node_actions = None
    
    def __init__(self, interfaces, config, resources, proot):
        self.interfaces, self.config, self.resources, self.proot = interfaces, config, resources, proot
        self.reqstring = "{action}/{privstate}/%s{other}" % resources("access")("show")[1]["port"]
        self.sessions = {}
        self.gui_node_actions = [
{"text":"private", "action": self.toggle_private, \
"interfaces": ["gtk",], "description": "Toggle private chat", "state": False},
{"text":"Delete log", "action": self.delete_log, \
"interfaces": ["gtk",], "description": "Delete the chat log"}
]
        self.gui = gtkstuff.gtkstuff(self)

    def cleanup(self, widget, certhash):
        del self.sessions[certhash]
        #port_to_answer = None

    def delete_log(self, gui, _addressfunc, window, certhash, dheader):
        if certhash not in self.sessions:
            return
        with self.sessions[certhash].lock:
            try:
                shutil.rmtree(os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash))
                #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
            except FileNotFoundError:
                pass
            self.sessions[certhash].buffer.remove_all()
        

    def toggle_private(self, gui, _addressfunc, window, certhash, state, dheader):
        if state:
            self.sessions[certhash].private = True
        else:
            self.sessions[certhash].private = False

    def gui_node_iface(self, guitype, _name, certhash, _addressfunc, _traversefunc, window):
        if guitype != "gtk":
            return None
            
        self.sessions[certhash] = hash_session(guitype, self,  _name, certhash, _addressfunc, _traversefunc, window)
        return self.sessions[certhash].init_gui()

    # not needed because routine
    def address_change(self, gui, _address, window, _hash):
        pass
    
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
                logging.error("Invalid filename")
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
    
        if certhash not in self.sessions:
            # if still not existent
            return
        self.sessions[certhash].init_pathes()
    
        with self.sessions[certhash].lock:
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
                    self.gui.gtk_receive_text(certhash, _text, private, timestamp)
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
                    self.gui.gtk_receive_img(certhash, _img, private, timestamp)
            elif action == "send_file":
                _name, _size = _rest.split("/", 1)
                if private == False:
                    with open (os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                        logob.write("rf:{timestamp}:{name},{size}\n".format(name=_name, size=_size, timestamp=timestamp))
                if "gtk" in self.interfaces and gtkstuff is not None:
                    self.gui.gtk_receive_file(certhash, _name, int(_size), private, timestamp)
    
    ## executed when redirected, return False, when redirect should not be executed
    # def rreceive(self, action, _socket, _cert, certhash):
    #     pass
    ### server:
    # def sreceive(self, action, _socket, _cert, certhash):
    #     pass
