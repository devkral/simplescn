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

from . import config
from .pwrequester import pwcallmethod
from .exceptions import InvalidLoadSizeError, InvalidLoadLevelError

from .tools import generate_certs, init_config_folder, \
dhash, SCNAuthServer, TraverserDropper, scnparse_url, default_sslcont, get_pidlock
from .tools.checks import check_certs, hashstr, check_local, namestr, check_updated_certs, destportint, addressstr, fastit
from ._decos import check_args_deco, classify_local, classify_private, classify_accessable, generate_validactions_deco
from .tools import generate_error, quick_error
from ._common import parsepath, parsebool, CommonSCN, CommonSCNHandler, SHTTPServer, loglevel_converter

@generate_validactions_deco
class Server(CommonSCN):
    # replace not add (multi instance)
    capabilities = None
    nhipmap = None
    nhipmap_cache = ""
    registered_addrs = None
    refreshthread = None
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
        raise NotImplementedError()

    def __init__(self, d):
        CommonSCN.__init__(self)
        self.capabilities = ["basic", "server"]
        # init here (multi instance situation)
        if config.sorteddict:
            self.nhipmap = config.sorteddict()
        else:
            self.nhipmap = dict()
        # needed only if traverse is active
        self.registered_addrs = set()
        self.nhipmap_cond = threading.Event()
        self.changeip_lock = threading.Lock()
        self.links = d["links"]
        self.notraverse_local = self.links["kwargs"]["notraverse_local"]
        # now: always None, because set manually
        #  traversesrcaddr = d.get("traversesrcaddr", None)
        if len(config.very_low_load) != 2 or len(config.low_load) != 3 or len(config.medium_load) != 3 or len(config.high_load) != 3:
            raise InvalidLoadSizeError()
        if config.high_load[0] < config.medium_load[0] or config.medium_load[0] < config.low_load[0]:
            raise InvalidLoadLevelError()
        if d["name"] is None or len(d["name"]) == 0:
            logging.debug("Name empty")
            d["name"] = "noname"
        self.timeout = self.links["kwargs"]["timeout"]
        self.connect_timeout = self.links["kwargs"]["connect_timeout"]
        self.priority = self.links["kwargs"]["priority"]
        self.name = d["name"]
        self.message = d["message"]
        self.cache["dumpnames"] = json.dumps({"items": [], "sorted": config.sorteddict is not None})
        self.update_cache()
        self.validactions.update(self.cache.keys())
        self.load_balance(0)
        self.refreshthread = threading.Thread(target=self.refresh_nhipmap, daemon=True)
        self.refreshthread.start()
        # now: traversesrcaddr always invalid, set manually by init
        #  if traversesrcaddr:
        #      self.traverse = TraverserDropper(traversesrcaddr)

    def __del__(self):
        CommonSCN.__del__(self)
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as exc:
            logging.error(exc)

    # private, do not include in validactions
    @classify_private
    def refresh_nhipmap(self):
        while self.isactive:
            count = 0
            dump = []
            issorted = config.sorteddict is not None
            istraverse = self.traverse is not None
            with self.changeip_lock:
                if istraverse:
                    self.registered_addrs.clear()
                e_time = int(time.time())-self.expire_time
                for _name, hashob in self.nhipmap.items():
                    for _hash, val in hashob.items():
                        if val["updatetime"] < e_time:
                            del self.nhipmap[_name][_hash]
                        else:
                            count += 1
                            dump.append((_name, _hash, val.get("security")))
                            if istraverse:
                                self.registered_addrs.add((val["address"], val["port"]))
                    if len(self.nhipmap[_name]) == 0:
                        del self.nhipmap[_name]
                ### don't annote list with "map" dict structure on serverside (overhead)
                self.cache["dumpnames"] = json.dumps({"items": dump, "sorted": issorted})
                self.cache["num_nodes"] = json.dumps({"count": count})
                self.cache["update_time"] = json.dumps({"time": int(time.time())})
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
            update_list = check_updated_certs(_address, _port, certhashlist, newhash=newhash, timeout=self.timeout, connect_timeout=self.connect_timeout, traversefunc=lambda ownaddr: self.traverse.send((_address, _port), ownaddr))
        except Exception as exc:
            logging.warning(exc)
            update_list = []
        if update_list in [None, []]:
            return

        update_time = int(time.time())
        # name is in self.nhipmap because called at last
        assert _name in self.nhipmap, "name is not in nhipmap after being entered by register"
        for _uhash, _usecurity in update_list:
            entry= {"security": _usecurity, "hash": newhash, "name": _name, "updatetime": update_time}
            with self.changeip_lock:
                self.nhipmap[_name][_uhash] = entry

        # notify that change happened
        self.nhipmap_cond.set()

    @check_args_deco({"name": namestr, "port": destportint}, optional={"update": fastit})
    @classify_accessable
    def register(self, obdict: dict):
        """ func: register client
            return: success or error
            name: client name
            port: listen port of client
            update: list with compromised hashes (includes reason=security) """
        if obdict["origcertinfo"][1] is None:
            return False, quick_error("no_cert")
        if obdict["clientaddress"][0][:7] == "::ffff:":
            caddress = (obdict["clientaddress"][0][7:], obdict["clientaddress"][1])
        else:
            caddress = obdict["clientaddress"]
        clientcerthash = obdict["origcertinfo"][1]
        ret = self.check_register((caddress[0], obdict["port"]), clientcerthash)
        if not ret[0]:
            ret = self.open_traversal({"clientaddress": ('', obdict["socket"].getsockname()[1]), "destaddr": "{}-{}".format(caddress[0], obdict["port"])})
            if not ret[0]:
                return ret
            ret = self.check_register((caddress[0], obdict["port"]), clientcerthash)
            if not ret[0]:
                return False, quick_error("unreachable client")
            use_traversal = True
        elif not self.notraverse_local and self.traverse and check_local(caddress[0]):
            use_traversal = True
        else:
            use_traversal = False
        entry = {}
        entry["address"] = caddress[0]
        entry["port"] = obdict["port"]
        entry["updatetime"] = int(time.time())
        entry["security"] = "valid"
        entry["traverse"] = use_traversal
        addrtupel = (caddress[0], obdict["port"])
        istraverse = self.traverse is not None
        _name = obdict["name"]
        # prepared dict, so no dict must be allocated while having lock
        if config.sorteddict:
            _prepdict = config.sorteddict()
        else:
            _prepdict = dict()
        _nhipmapneedupdate = False
        with self.changeip_lock:
            if _name not in self.nhipmap:
                self.nhipmap[_name] = _prepdict
            # update only if not in db or if valid
            if clientcerthash not in self.nhipmap[_name]:
                # set security=valid for next step
                self.nhipmap[_name][clientcerthash] = entry
                _nhipmapneedupdate = True
                if istraverse:
                    self.registered_addrs.add(addrtupel)
            elif self.nhipmap[_name][clientcerthash].get("security", "valid") == "valid":
                self.nhipmap[_name][clientcerthash] = entry
                if istraverse:
                    self.registered_addrs.add(addrtupel)
        # update broken certs afterwards (if needed)
        if len(obdict.get("update", [])) > 0:
            threading.Thread(target=self.check_brokencerts, args=(caddress[0], obdict["port"], obdict["name"], obdict.get("update", []), clientcerthash), daemon=True).start()

        # notify that a change happened if needed
        if _nhipmapneedupdate:
            self.nhipmap_cond.set()
        return True, {"traverse_needed": use_traversal}

    @check_args_deco({"destaddr": addressstr})
    @classify_accessable
    def open_traversal(self, obdict: dict):
        """ func: open traversal connection
            return: traverse_address (=remote own address)
            destaddr: destination address """
        if self.traverse is None:
            return False, quick_error("no traversal possible")
        try:
            destaddr = scnparse_url(obdict.get("destaddr"), True)
        except Exception:
            return False, quick_error("destaddr invalid")
        if destaddr not in self.registered_addrs:
            return False, quick_error("destaddr is not registered")
        travaddr = obdict.get("clientaddress")
        threading.Thread(target=self.traverse.send, args=(travaddr, destaddr), daemon=True).start()
        return True, {"traverseaddress": travaddr}

    @check_args_deco()
    @classify_local
    @classify_accessable
    def get_ownaddr(self, obdict: dict):
        """ func: return remote own address
            return: remote requester address """
        return True, {"address": obdict.get("clientaddress")}

    @check_args_deco({"hash": str, "name": namestr})
    @classify_accessable
    def get(self, obdict: dict):
        """ func: get address of a client
            return: client address, client port, security, traverse_address, traverse_needed
            name: client name
            hash: client hash
            autotraverse: open traversal when necessary (default: True) """
        if obdict["name"] not in self.nhipmap:
            return False, quick_error("name not found")
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, quick_error("hash not found")
        _obj = self.nhipmap[obdict["name"]][obdict["hash"]]
        retob = {"security": _obj.get("security", "valid")}
        if _obj.get("security", "") != "valid":
            retob["name"] = _obj["name"]
            retob["hash"] = _obj["hash"]
            _obj = self.nhipmap[_obj["name"]][_obj["hash"]]
        retob["pureaddress"] = _obj["address"]
        retob["port"] = _obj["port"]

        if self.traverse and _obj["traverse"]:
            retob["traverse_needed"] = True
        else:
            retob["traverse_needed"] = False
        return True, retob

def gen_ServerHandler(_links):
    class ServerHandler(CommonSCNHandler):
        server_version = 'simplescn/1.0 (server)'
        links = _links
        server_timeout = _links["kwargs"]["server_timeout"]
        etablished_timeout = _links["kwargs"]["timeout"]

        def handle_server(self, action):
            if action not in self.links["server_server"].validactions:
                self.scn_send_answer(400, message="invalid action - server")
                return
            if not self.links["auth_server"].verify(self.auth_info):
                # TODO: client cannot ask pw for two nodes (open_traversal)
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
                jsonnized = json.dumps(result)
            except Exception as exc:
                # with harden mode do not show errormessage
                if config.harden_mode:
                    # create unknown error object
                    generror = {"msg": "unknown", "type": "unknown"}
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
    return ServerHandler

class ServerInit(object):
    config_path = None
    links = None
    pidpath = None

    @classmethod
    def create(cls, **kwargs):
        if not kwargs["nolock"]:
            # port
            pidpath = os.path.join(kwargs["run"], "{}-simplescn-server.lck".format(kwargs["port"]))
            pidl = get_pidlock(pidpath)
            if not pidl:
                logging.info("Server already active or permission problems")
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
        self.links["config_root"] = kwargs["config"]
        self.links["kwargs"] = kwargs
        self.links["handler"] = gen_ServerHandler(self.links)
        _spath = os.path.join(self.links["config_root"], "server")

        init_config_folder(self.links["config_root"], "server")
        if not check_certs(_spath+"_cert"):
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_spath + "_cert")
            logging.debug("Certificate generation complete")
        with open(_spath+"_cert.pub", 'r') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip()
        self.links["auth_server"] = SCNAuthServer(dhash(pub_cert))
        if bool(kwargs["spwhash"]):
            if kwargs["spwhash"] not in hashstr:
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
        if len(_name) > 2 or _name[0] not in namestr:
            logging.error("Configuration error in %s\nshould be: <name>/<port>\nor name contains some restricted characters", _spath + "_name")

        if kwargs["port"] > -1:
            port = kwargs["port"]
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = config.server_port

        self.links["certtupel"] = (config.isself, dhash(pub_cert), pub_cert)
        serverd = {"name": _name[0], "message":_message, "links": self.links}
        self.links["server_server"] = Server(serverd)

        sslcont = default_sslcont()
        sslcont.load_cert_chain(_spath+"_cert.pub", _spath+"_cert.priv", lambda pwmsg: bytes(pwcallmethod(config.pwdecrypt_prompt), "utf-8"))

        self.links["hserver"] = SHTTPServer(("::", port), sslcont, self.links["handler"])

        if not kwargs["notraversal"]:
            self.links["server_server"].capabilities.append("traversal")
            srcaddr = self.links["hserver"].socket.getsockname()
            self.links["server_server"].traverse = TraverserDropper(srcaddr)

        self.links["hserver"].serve_forever_nonblock()

    def quit(self):
        """ clean quit, close everything. Failsave if not called exist (__del__ stuff) """
        if not self.links["server_server"].isactive:
            return
        self.links["server_server"].isactive = False
        self.links["hserver"].server_close()

    def show(self):
        """ show server info """
        ret = dict()
        ret["cert_hash"] = self.links["certtupel"][1]
        hserver = self.links["hserver"]
        ret["hserver"] = hserver.server_name, hserver.server_port
        ret["name"] = self.links["server_server"].name
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
    "nolock": ["False", parsebool, "<bool>: deactivate port lock"],
    "notraverse_local": ["False", parsebool, "<bool>: don't enable traverse for clients on localhost"]}

def server_paramhelp():
    _temp = "# parameters\n"
    for _key, elem in sorted(default_server_args.items(), key=lambda x: x[0]):
        _temp += "  * key: {}, value: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return _temp
