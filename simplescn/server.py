#! /usr/bin/env python3

"""
server stuff
license: MIT, see LICENSE.txt
"""

import os

import time
import threading
import json
import logging
import ssl


from simplescn import config, InvalidLoadSizeError, InvalidLoadLevelError, pwcallmethod

from simplescn.tools import generate_certs, init_config_folder, \
dhash, scnauth_server, traverser_dropper, scnparse_url, default_sslcont, get_pidlock
from simplescn.tools.checks import check_certs, check_hash, check_local, check_name, check_updated_certs
from simplescn._decos import check_args_deco, classify_local, classify_private, classify_accessable, generate_validactions_deco
from simplescn.tools import generate_error, gen_result
from simplescn._common import parsepath, parsebool, commonscn, commonscnhandler, http_server, loglevel_converter

@generate_validactions_deco
class server(commonscn):
    # replace not add (multi instance)
    capabilities = None
    nhipmap = None
    nhipmap_cache = ""
    refreshthread = None
    cert_hash = None
    scn_type = "server"
    traverse = None
    links = None
    timeout = None
    connect_timeout = None

    # auto set by load balancer
    expire_time = None
    sleep_time = None

    @property
    def validactions(self):
        raise NotImplementedError

    def __init__(self, d):
        commonscn.__init__(self)
        self.capabilities = ["basic", "server"]
        # init here (multi instance situation)
        self.nhipmap = {}
        self.nhipmap_cond = threading.Event()
        self.changeip_lock = threading.Lock()
        # now: always None, because set manually
        #  traversesrcaddr = d.get("traversesrcaddr", None)
        if len(config.very_low_load) != 2 or len(config.low_load) != 3 or len(config.medium_load) != 3 or len(config.high_load) != 3:
            raise InvalidLoadSizeError()
        if config.high_load[0] < config.medium_load[0] or config.medium_load[0] < config.low_load[0]:
            raise InvalidLoadLevelError()
        if d["name"] is None or len(d["name"]) == 0:
            logging.debug("Name empty")
            d["name"] = "<noname>"
        if d["message"] is None or len(d["message"]) == 0:
            logging.debug("Message empty")
            d["message"] = "<empty>"

        self.timeout = d["timeout"]
        self.connect_timeout = d["connect_timeout"]
        self.priority = int(d["priority"])
        self.certtupel = d["certtupel"]
        self.name = d["name"]
        self.message = d["message"]
        self.links = d["links"]
        self.cache["dumpnames"] = json.dumps({})
        self.update_cache()
        self.validactions.update(self.cache.keys())
        self.load_balance(0)
        self.refreshthread = threading.Thread(target=self.refresh_nhipmap, daemon=True)
        self.refreshthread.start()
        # now: traversesrcaddr always invalid, set manually by init
        #  if traversesrcaddr:
        #      self.traverse = traverser_dropper(traversesrcaddr)

    def __del__(self):
        commonscn.__del__(self)
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as exc:
            logging.error(exc)

    # private, do not include in validactions
    @classify_private
    def refresh_nhipmap(self):
        while self.isactive:
            self.changeip_lock.acquire()
            e_time = int(time.time())-self.expire_time
            count = 0
            dump = []
            for _name, hashob in self.nhipmap.items():
                for _hash, val in hashob.items():
                    if val["updatetime"] < e_time:
                        del self.nhipmap[_name][_hash]
                    else:
                        count += 1
                        dump.append((_name, _hash, val.get("security")))
                if len(self.nhipmap[_name]) == 0:
                    del self.nhipmap[_name]
            ### don't annote list with "map" dict structure on serverside (overhead)
            self.cache["dumpnames"] = json.dumps(dump)
            self.cache["num_nodes"] = json.dumps(count)
            self.cache["update_time"] = json.dumps(int(time.time()))
            self.changeip_lock.release()
            self.nhipmap_cond.clear()
            self.load_balance(count)
            time.sleep(self.sleep_time)
            # wait until hashes change
            self.nhipmap_cond.wait()

    # private, do not include in validactions
    @classify_private
    def load_balance(self, size_nh):
        if size_nh >= config.high_load[0]:
            self.sleep_time, self.expire_time = config.high_load[1:]
        elif size_nh >= config.medium_load[0]:
            self.sleep_time, self.expire_time = config.medium_load[1:]
        elif size_nh >= config.low_load[0]:
            self.sleep_time, self.expire_time = config.low_load[1:]
        else:
            # very_low_load tuple mustn't have three items
            self.sleep_time, self.expire_time = config.very_low_load

    # private, do not include in validactions
    @classify_private
    def check_register(self, addresst, _hash):
        try:
            _cert = ssl.get_server_certificate(addresst, ssl_version=ssl.PROTOCOL_TLSv1_2).strip().rstrip()
        except ConnectionRefusedError:
            return False, "use_traversal"
        except ssl.SSLError:
            return False, "use_traversal"
        if dhash(_cert) != _hash:
            return False, "hash_mismatch"
        return True, "registered_ip"

    # private: don't include
    @classify_private
    def check_brokencerts(self, _address, _port, _name, certhashlist, newhash):
        """ func: connect to check if requester has broken certs """
        try:
            update_list = check_updated_certs(_address, _port, certhashlist, newhash=newhash, timeout=self.timeout, connect_timeout=self.connect_timeout, traversefunc=lambda ownaddr:self.traverse.send((_address, _port), ownaddr))
        except Exception as exc:
            logging.warning(exc)
            update_list = []
        if update_list in [None, []]:
            return

        self.changeip_lock.acquire(True)
        update_time = int(time.time())
        for _uhash, _usecurity in update_list:
            self.nhipmap[_name][_uhash] = {"security": _usecurity, "hash": newhash, "name": _name, "updatetime": update_time}
        self.changeip_lock.release()
        # notify that change happened
        self.nhipmap_cond.set()

    @check_args_deco({"name": str, "port": int}, optional={"update": list})
    @classify_accessable
    def register(self, obdict: dict):
        """ func: register client
            return: success or error
            name: client name
            port: listen port of client
            update: list with compromised hashes (includes reason=security) """
        if not check_name(obdict["name"]):
            return False, generate_error("invalid_name", False)
        if obdict["client_certhash"] is None:
            return False, generate_error("no_cert", False)
        if obdict["clientaddress"][0][:7] == "::ffff:":
            caddress = (obdict["clientaddress"][0][7:], obdict["clientaddress"][1])
        else:
            caddress = obdict["clientaddress"]
        clientcerthash = obdict["client_certhash"]
        ret = self.check_register((caddress[0], obdict["port"]), clientcerthash)
        if not ret[0]:
            # '' = serveraddress
            ret = self.open_traversal({"clientaddress": ('', obdict["socket"].getsockname()[1]), "destaddr": "{}-{}".format(caddress[0], obdict["port"])})
            if not ret[0]:
                return ret
            ret = self.check_register((caddress[0], obdict["port"]), clientcerthash)
            if not ret[0]:
                return False, generate_error("unreachable client", False)
            mode = "registered_traversal"
        elif check_local(caddress[0]):
            mode = "registered_traversal"
        else:
            mode = "registered_ip"
        self.changeip_lock.acquire(False)
        update_time = int(time.time())
        if obdict["name"] not in self.nhipmap:
            self.nhipmap[obdict["name"]] = {}
        if clientcerthash not in self.nhipmap[obdict["name"]]:
            # set security=valid for next step
            self.nhipmap[obdict["name"]][clientcerthash] = {"security": "valid"}
        # when certificate has a compromised flag (!=valid) stop register process
        if self.nhipmap[obdict["name"]][clientcerthash].get("security", "valid") == "valid":
            self.nhipmap[obdict["name"]][clientcerthash]["address"] = caddress[0]
            self.nhipmap[obdict["name"]][clientcerthash]["port"] = obdict["port"]
            self.nhipmap[obdict["name"]][clientcerthash]["updatetime"] = update_time
            self.nhipmap[obdict["name"]][clientcerthash]["security"] = "valid"
            self.nhipmap[obdict["name"]][clientcerthash]["traverse"] = mode == "registered_traversal"
        self.changeip_lock.release()

        # update broken certs afterwards
        threading.Thread(target=self.check_brokencerts, args=(caddress[0], obdict["port"], obdict["name"], obdict.get("update", []), clientcerthash), daemon=True).start()

        # notify that change happened
        self.nhipmap_cond.set()
        return True, {"mode": mode, "traverse": mode == "registered_traversal"}

    @check_args_deco({"destaddr": str}) #, optional={"port": int}
    @classify_accessable
    def open_traversal(self, obdict: dict):
        """ func: open traversal connection
            return: traverse_address (=remote own address)
            destaddr: destination address """
        if self.traverse is None:
            return False, generate_error("no traversal possible", False)
        try:
            destaddr = scnparse_url(obdict.get("destaddr"), True)
        except Exception:
            return False, generate_error("destaddr invalid", False)
        travaddr = obdict.get("clientaddress") #(obdict["clientaddress"][0], travport)
        threading.Thread(target=self.traverse.send, args=(travaddr, destaddr), daemon=True).start()
        return True, {"traverse_address": travaddr}

    @check_args_deco()
    @classify_local
    @classify_accessable
    def get_ownaddr(self, obdict: dict):
        """ func: return remote own address
            return: remote requester address """
        return True, {"address": obdict.get("clientaddress")}

    @check_args_deco({"hash": str, "name": str}, optional={"autotraverse": bool})
    @classify_accessable
    def get(self, obdict: dict):
        """ func: get address of a client
            return: client address, client port, security, traverse_address, traverse_needed
            name: client name
            hash: client hash
            autotraverse: open traversal when necessary (default: False) """
        if obdict["name"] not in self.nhipmap:
            return False, generate_error("name not exist", False)
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, generate_error("hash not exist", False)
        _obj = self.nhipmap[obdict["name"]][obdict["hash"]]
        if _obj.get("security", "") != "valid":
            _usecurity, _uname, _uhash = _obj.get("security"), _obj["name"], _obj["hash"]
            _obj = self.nhipmap[_obj["name"]][_obj["hash"]]
        else:
            _usecurity = None
        _travaddr = None
        if self.traverse and _obj.get("autotraverse", False):
            _travobj1 = self.open_traversal(obdict)
            if _travobj1[0]:
                _travaddr = _travobj1[1].get("traverse_address")
        if _usecurity:
            return True, {"address": _obj["address"], "security": _usecurity, "port": _obj["port"], "name": _uname, "hash": _uhash, "traverse_needed": _obj["traverse"], "traverse_address":_travaddr}
        else:
            return True, {"address": _obj["address"], "security": "valid", "port": _obj["port"], "traverse_needed": _obj["traverse"], "traverse_address":_travaddr}

def gen_server_handler(_links, stimeout, etimeout):
    class server_handler(commonscnhandler):
        server_version = 'simplescn/1.0 (server)'
        webgui = False
        links = _links
        server_timeout=stimeout
        etablished_timeout=etimeout

        def handle_server(self, action):
            if action not in self.links["server_server"].validactions:
                self.scn_send_answer(400, message="invalid action - server")
                return
            if not self.links["auth_server"].verify(self.auth_info):
                authreq = self.links["auth_server"].request_auth()
                ob = bytes(json.dumps(authreq), "utf-8")
                self.scn_send_answer(401, body=ob, docache=False)
                return
            self.connection.settimeout(self.etablished_timeout)
            if action in self.links["server_server"].cache:
                # cleanup {} or smaller, protect against big transmissions
                self.cleanup_stale_data(2)
                ob = bytes(self.links["server_server"].cache[action], "utf-8")
                self.scn_send_answer(200, body=ob, docache=False)
                return

            obdict = self.parse_body(config.max_serverrequest_size)
            if obdict is None:
                return None
            try:
                func = getattr(self.links["server_server"], action)
                success, result = func(obdict)[:2]
                jsonnized = json.dumps(gen_result(result))
            except Exception as exc:
                # with harden mode do not show errormessage
                if config.harden_mode:
                    generror = generate_error("unknown")
                else:
                    shallstack = config.debug_mode and \
                        (check_local(self.client_address[0]))
                    generror = generate_error(exc, shallstack)
                ob = bytes(json.dumps(generror), "utf-8")
                self.scn_send_answer(500, body=ob, mime="application/json", docache=False)
                return
            ob = bytes(jsonnized, "utf-8")
            if not success:
                self.scn_send_answer(400, body=ob, mime="application/json", docache=False)
            else:
                self.scn_send_answer(200, body=ob, mime="application/json", docache=False)

        def do_POST(self):
            if not self.init_scn_stuff():
                self.connection.settimeout(self.server_timeout)
                return
            splitted = self.path[1:].split("/", 1)
            if len(splitted) == 1:
                resource = splitted[0]
                sub = ""
            else:
                resource = splitted[0]
                sub = splitted[1]
            if resource == "usebroken":
                # for invalidating and updating, don't use connection afterwards
                self.handle_usebroken(sub)
            elif resource == "server":
                self.handle_server(sub)
            else:
                self.scn_send_answer(404, message="resource not found (POST)", docache=True)
            self.connection.settimeout(self.server_timeout)
    return server_handler

class server_init(object):
    config_path = None
    links = None
    active = True
    pidpath = None

    @classmethod
    def create(cls, **kwargs):
        if not kwargs["nolock"]:
            # port
            pidpath = get_pidlock(kwargs["run"], "{}-simplescn-server.lck".format(kwargs["port"]))
            if not pidpath:
                return None
        else:
            pidpath = None
        ret = cls(**kwargs)
        ret.pidpath = pidpath
        return ret
    
    def __del__(self):
        if self.pidpath:
            try:
                os.remove(self.pidpath)
            except Exception:
                pass

    def __init__(self, **kwargs):
        self.links = {}
        self.links["config_root"] = kwargs.get("config")
        self.links["kwargs"] = kwargs
        self.links["handler"] = gen_server_handler(self.links, kwargs.get("server_timeout"), kwargs.get("default_timeout"))
        _spath = os.path.join(self.links["config_root"], "server")

        init_config_folder(self.links["config_root"], "server")
        if not check_certs(_spath+"_cert"):
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_spath + "_cert")
            logging.debug("Certificate generation complete")
        with open(_spath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip()
        self.links["auth_server"] = scnauth_server(dhash(pub_cert))
        if bool(kwargs["spwhash"]):
            if not check_hash(kwargs["spwhash"]):
                logging.error("hashtest failed for spwhash, spwhash: %s", kwargs["spwhash"])
            else:
                self.links["auth_server"].init(kwargs["spwhash"])
        elif bool(kwargs["spwfile"]):
            with open(kwargs["spwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init(dhash(pw))

        _message = None
        _name = None
        with open(_spath+"_name.txt", 'r') as readserver:
            _name = readserver.readline().strip().rstrip()
        with open(_spath+"_message.txt", 'r') as readservmessage:
            _message = readservmessage.read()
        if None in [pub_cert, _name, _message]:
            raise Exception("missing")
        _name = _name.split("/")
        if len(_name) > 2 or not check_name(_name):
            logging.error("Configuration error in %s\nshould be: <name>/<port>\nor name contains some restricted characters", _spath + "_name")

        if kwargs["port"] > -1:
            port = kwargs["port"]
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = config.server_port

        certtupel = (config.isself, dhash(pub_cert), pub_cert)
        serverd = {"name": _name[0], "certtupel": certtupel, "timeout": kwargs["timeout"], "connect_timeout": kwargs["connect_timeout"], "priority": kwargs["priority"], "message":_message, "links": self.links}
        self.links["server_server"] = server(serverd)
        
        sslcont = default_sslcont()
        sslcont.load_cert_chain( _spath+"_cert.pub",  _spath+"_cert.priv", lambda pwmsg: bytes(pwcallmethod(config.pwdecrypt_prompt), "utf-8"))

        self.links["hserver"] = http_server(("::", port), sslcont, self.links["handler"])

        if not kwargs["notraversal"]:
            self.links["server_server"].capabilities.append("traversal")
            srcaddr = self.links["hserver"].socket.getsockname()
            self.links["server_server"].traverse = traverser_dropper(srcaddr)

        self.links["hserver"].serve_forever_nonblock()

    def quit(self):
        # server may need some time to cleanup, elsewise strange exceptions appear
        if not self.active:
            return
        self.active = False
        self.links["hserver"].server_close()

    def show(self):
        ret = dict()
        ret["cert_hash"] = self.links["server_server"].certtupel[1]
        _r = self.links["hserver"]
        ret["hserver"] = _r.server_name, _r.server_port
        return ret
    def join(self):
        self.links["hserver"].serve_join()

#### don't base on sqlite as it increases complexity and needed libs

default_server_args = {
    "config": [config.default_configdir, parsepath, "<path>: path to config dir"],
    "port": [str(-1), int, "<int>: port of server, -1: use port in \"server_name.txt\""],
    "spwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than pwfile, lowercase"],
    "spwfile": ["", str, "<file>: file with password (cleartext)"],
    "priority": [str(config.default_priority), int, "<int>: set server priority"],
    "connect_timeout": [str(config.connect_timeout), int, "<int>: set timeout for connecting"],
    "server_timeout": [str(config.server_timeout), int, "<int>: set timeout for servercomponent"],
    "timeout": [str(config.default_timeout), int, "<int>: set default timeout (etablished connections)"],
    "loglevel": [str(config.default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "run": [config.default_runpath, parsepath, "<dir>: path where unix socket and pid are saved"],
    "notraversal": ["False", parsebool, "<bool>: disable traversal"],
    "nolock": ["False", parsebool, "<bool>: deactivate port lock"]}

def server_paramhelp():
    _temp = "# parameters\n"
    for _key, elem in sorted(default_server_args.items(), key=lambda x: x[0]):
        _temp += "  * key: {}, value: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return _temp

