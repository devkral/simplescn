#! /usr/bin/env python3
"""
main client stuff (client)
license: MIT, see LICENSE.txt
"""

import sys
import os
import socket
import threading
import json
import logging

from simplescn import config, VALError, AuthNeeded, AddressError, pwcallmethod
from simplescn.config import isself, file_family
from simplescn._common import parsepath, parsebool, commonscn, commonscnhandler, http_server, generate_error, gen_result, certhash_db, loglevel_converter, permissionhash_db


from simplescn.tools import default_sslcont, try_traverse, get_pidlock, generate_certs, \
init_config_folder, dhash, rw_socket, scnauth_server, traverser_helper
from simplescn.tools.checks import check_certs, check_name, check_hash, check_local, check_classify
from simplescn._decos import check_args_deco, classify_local, classify_accessable, classify_private, generate_validactions_deco
from simplescn._client_admin import client_admin
from simplescn._client_safe import client_safe
from simplescn.scnrequest import requester


@generate_validactions_deco
class client_client(client_admin, client_safe):
    name = None
    cert_hash = None
    hashdb = None
    links = None
    scntraverse_helper = None
    brokencerts = None
    _cache_help = None
    requester = None

    @property
    def validactions(self):
        raise NotImplementedError

    def __init__(self, name: str, pub_cert_hash: str, _links: dict):
        client_admin.__init__(self)
        client_safe.__init__(self)
        self.validactions.update(client_admin.validactions)
        self.validactions.update(client_safe.validactions)
        self.links = _links
        self.name = name
        self.cert_hash = pub_cert_hash
        self.hashdb = certhash_db(os.path.join(self.links["config_root"], "certdb.sqlite"))
        self.brokencerts = []
        self.requester = requester(ownhash=self.cert_hash, hashdb=self.hashdb, certcontext=self.links["hserver"].sslcont)

        self.udpsrcsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.udpsrcsock.settimeout(None)
        self.udpsrcsock.bind(self.links["hserver"].socket.getsockname())
        self.scntraverse_helper = traverser_helper(connectsock=self.links["hserver"].socket, srcsock=self.udpsrcsock)
        
        os.makedirs(os.path.join(self.links["config_root"], "broken"), mode=0o700, exist_ok=True)
        for elem in os.listdir(os.path.join(self.links["config_root"], "broken")):
            _splitted = elem.rsplit(".", 1)
            if _splitted[1] != "reason":
                continue
            _hash = _splitted[0]
            with open(os.path.join(self.links["config_root"], "broken", elem), "r") as reado:
                _reason = reado.read().strip().rstrip()
            if check_hash(_hash) and (_hash, _reason) not in self.brokencerts:
                self.brokencerts.append((_hash, _reason))
        self._cache_help = self.cmdhelp()

    # return success, body, (name, security), hash
    # return success, body, isself, hash
    # return success, body, None, hash
    def do_request(self, addr_or_con, path: str, body=None, headers=None, forceport=False, forcehash=None, forcetraverse=False, sendclientcert=False):
        """ func: wrapper+ cache certcontext and ownhash """
        return self.requester.do_request_simple(addr_or_con, path, body, headers, forceport=forceport, forcehash=forcehash, forcetraverse=forcetraverse, sendclientcert=sendclientcert)

    @classify_private
    def access_dict(self, action, obdict):
        """ internal method to access functions """
        if action in self.validactions:
            gaction = getattr(self, action)
            if check_classify(gaction, "private"):
                return False, "actions: 'private functions not allowed in access", isself, self.cert_hash
            #with self.client_lock: # not needed, use sqlite's intern locking mechanic
            try:
                return gaction(obdict)
            except AuthNeeded as exc:
                raise exc
            except Exception as exc:
                #raise(exc)
                return False, exc #.with_traceback(sys.last_traceback)
        else:
            return False, "not in validactions", isself, self.cert_hash
    @classify_private
    def access_main(self, action, **obdict):
        return self.access_dict(action, obdict)
    # help section
    def cmdhelp(self):
        out = "# commands\n"
        for funcname in sorted(self.validactions):
            func = getattr(self, funcname)
            if getattr(func, "__doc__", None) is not None:
                out += "{doc}\n".format(doc=func.__doc__)
            else:
                logging.info("Missing __doc__: %s", funcname)
        return out

### receiverpart of client ###

@generate_validactions_deco
class client_server(commonscn):
    spmap = None
    scn_type = "client"
    links = None
    # replace commonscn capabilities
    capabilities = None

    wlock = None

    @property
    def validactions(self):
        raise NotImplementedError

    def __init__(self, dcserver):
        commonscn.__init__(self)
        # init here (multi instance situation)
        self.spmap = {}
        self.wlock = threading.Lock()
        self.links = dcserver["links"]
        self.capabilities = ["basic", "client", "trust"]
        if not self.links["kwargs"].get("nowrap", False):
            self.capabilities.append("wrap")
        if not self.links["kwargs"].get("notraversal", False):
            self.capabilities.append("traversal")
        if self.links["kwargs"].get("trustforall", False):
            self.capabilities.append("trustforall")

        if dcserver["name"] is None or len(dcserver["name"]) == 0:
            logging.info("Name empty")
            dcserver["name"] = "<noname>"
        if dcserver["message"] is None or len(dcserver["message"]) == 0:
            logging.info("Message empty")
            dcserver["message"] = "<empty>"
        self.name = dcserver["name"]
        self.message = dcserver["message"]
        self.priority = dcserver["priority"]
        self.cert_hash = dcserver["cert_hash"]
        self.cache["dumpservices"] = json.dumps({})
        self.update_cache()
        self.validactions.update(self.cache.keys())
    ### the primary way to add or remove a service
    ### can be called by every application on same client
    ### don't annote list with "map" dict structure on serverside (overhead)

    @check_args_deco({"name": str, "port": int}, optional={"wrappedport": bool,"post": bool})
    @classify_local
    @classify_accessable
    def registerservice(self, obdict):
        """ func: register a service = (map port to name)
            return: success or error
            name: service name
            port: port number
            wrappedport: port is not shown/is not traversable (but can be wrapped)
            post: send http post request with certificate in header to service (activates wrappedport if not explicitly deactivated) """
        if check_local(obdict["clientaddress"][0]):
            with self.wlock:
                wrappedport = obdict.get("wrappedport", None)
                # activates wrappedport if unspecified
                if wrappedport is None:
                    wrappedport = obdict.get("post", False)
                self.spmap[obdict.get("name")] = (obdict.get("port"), wrappedport, obdict.get("post", False))
                self.cache["dumpservices"] = json.dumps(self.spmap)
                #self.cache["listservices"] = json.dumps(gen_result(sorted(self.spmap.items(), key=lambda t: t[0]), True))
            return True, "ok"
        return False, "no permission"

    # don't annote list with "map" dict structure on serverside (overhead)
    @check_args_deco({"name": str})
    @classify_local
    @classify_accessable
    def delservice(self, obdict):
        """ func: delete a service
            return: success or error
            name: service name """
        if check_local(obdict["clientaddress"][0]):
            with self.wlock:
                if obdict["name"] in self.spmap:
                    del self.spmap[obdict["name"]]
                    self.cache["dumpservices"] = json.dumps(gen_result(self.spmap)) #sorted(self.spmap.items(), key=lambda t: t[0]), True))
            return True, "ok"
        return False, "no permission"

    ### management section - end ###

    @check_args_deco({"hash": str})
    @classify_accessable
    @classify_local
    def trust(self, obdict: dict):
        if not self.links["kwargs"].get("trustforall", False):
            if not "client_certhash" in obdict:
                return False, "no certificate sent"
            if not self.links["trusteddb"].exist(obdict.get("client_certhash"), "gettrust"):
                return False, "No permission"
        hasho = self.links["client"].hashdb.get(obdict.get("hash"))
        if hasho:
            return True, hasho[3]
        else:
            return True, "unknown"

    @check_args_deco({"name": str})
    @classify_local
    @classify_accessable
    def getservice(self, obdict):
        """ func: get the port of a service
            return: portnumber or negative for invisibleport
            name: servicename """
        serviceob = self.spmap.get(obdict["name"], tuple())
        if not bool(serviceob):
            return False, "Service not available"

        if not serviceob[1]:
            return True, serviceob[0]
        else:
            return True, -1

    @check_args_deco({"name": str})
    #@classify_accessable
    def traverse_service(self, obdict):
        """ func: traverse to the port of a service
            return: portnumber or error
            name: servicename """
        if not self.links["kwargs"]["notraversal"]:
            return False, "traversal disabled"
        serviceob = self.spmap.get(obdict["name"], tuple())
        if not bool(serviceob) or not serviceob[1]:
            return False, "Service not available"
        #_port = obdict.get("destport", None)
        #if not _port:
        #    _port = obdict["clientaddress"][1]
        travaddr = ('', serviceob[0])
        destaddr = obdict["clientaddress"] #(obdict["clientaddress"][0], _port)
        if try_traverse(travaddr, destaddr, connect_timeout=self.links["kwargs"]["connect_timeout"], retries=config.traverse_retries):
            return True, serviceob[0]
        else:
            return False, "Traversal could not opened"


def gen_client_handler(_links, stimeout, etimeout, server=False, client=False, remote=False, nowrap=False):
    """ create handler with: links, server_timeout, default_timeout, ... """
    class client_handler(commonscnhandler):
        """ client handler """
        server_version = 'simplescn/1.0 (client)'
        # set onlylocal variable if remote is deactivated and not server
        onlylocal = not remote and not server
        links = _links
        server_timeout = stimeout
        etablished_timeout = etimeout
        
        def handle_wrap(self, servicename):
            """ wrap service """
            service = self.links["client_server"].spmap.get(servicename, None)
            if service is None:
                # send error
                self.scn_send_answer(404, message="service not available")
                return
            port = service[0]
            sockd = None
            for addr in ["::1", "127.0.0.1"]:
                try:
                    # handles udp, tcp, ipv6, ipv4 so use this instead own solution
                    sockd = socket.create_connection((addr, port), self.links["kwargs"].get("connect_timeout"))
                    break
                except Exception as e:
                    logging.debug(e)
                    sockd = None
            if sockd is None:
                self.scn_send_answer(404, message="service not reachable")
                return
            sockd.settimeout(self.links["kwargs"].get("timeout"))
            redout = threading.Thread(target=rw_socket, args=(self.connection, sockd), daemon=True)
            redout.run()
            rw_socket(sockd, self.connection)

        if client:
            def handle_client(self, action):
                """ access to client_client """
                if action not in self.links["client"].validactions:
                    self.scn_send_answer(400, message="invalid action - client", docache=True)
                    return
                if remote:
                    gaction = getattr(self.links["client"], action)
                    if check_classify(gaction, "admin"):
                        ret = self.links["trusteddb"].exist(self.client_certhash, "admin")
                    else:
                        ret = self.links["trusteddb"].exist(self.client_certhash, "client")
                    if not ret:
                        self.send_error(400, "no permission - client")
                        return
                elif not remote and not check_local(self.client_address[0]):
                    self.send_error(400, "no permission - client")
                    return
                self.connection.settimeout(self.etablished_timeout)
                obdict = self.parse_body()
                if obdict is None:
                    return
                try:
                    response = self.links["client"].access_dict(action, obdict)
                except AuthNeeded as exc:
                    self.scn_send_answer(401, body=bytes(exc.reqob, "utf-8", errors="ignore"), mime="application/json", docache=False)
                    return

                if not response[0]:
                    error = response[1]
                    # with harden mode do not show errormessage
                    if config.harden_mode and not isinstance(error, (AddressError, VALError)):
                        resultob = generate_error("unknown")
                    else:
                        shallstack = config.debug_mode and \
                            (self.server.address_family != file_family or check_local(self.client_address[0])) \
                            and isinstance(error, (AddressError, VALError))
                        resultob = generate_error(error, shallstack)
                    status = 500
                else:
                    resultob = gen_result(response[1])
                    status = 200
                jsonnized = bytes(json.dumps(resultob), "utf-8")
                self.scn_send_answer(status, body=jsonnized, mime="application/json", docache=False)
        if server:
            def handle_server(self, action):
                """ access to client_server """
                if action not in self.links["client_server"].validactions:
                    self.scn_send_answer(400, message="invalid action - server", docache=True)
                    return
                if not self.links["auth_server"].verify(self.auth_info):
                    authreq = self.links["auth_server"].request_auth()
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                    return
                self.connection.settimeout(self.etablished_timeout)
                if action in self.links["client_server"].cache:
                    # cleanup {} or smaller, protect against big transmissions
                    self.cleanup_stale_data(2)
                    ob = bytes(self.links["client_server"].cache[action], "utf-8")
                    self.scn_send_answer(200, body=ob, docache=False)
                    return

                obdict = self.parse_body(config.max_serverrequest_size)
                if obdict is None:
                    return None
                try:
                    # no complicated checks here
                    func = getattr(self.links["client_server"], action)
                    response = func(obdict)
                    jsonnized = json.dumps(response[1])
                except Exception as exc:
                    # with harden mode do not show errormessage
                    if config.harden_mode and not isinstance(exc, (AddressError, VALError)):
                        generror = generate_error("unknown")
                    else:
                        shallstack = config.debug_mode and \
                            (self.server.address_family != file_family or check_local(self.client_address[0])) \
                            and isinstance(exc, (AddressError, VALError))
                        generror = generate_error(exc, shallstack)
                    ob = bytes(json.dumps(generror), "utf-8")
                    self.scn_send_answer(500, body=ob, mime="application/json")
                    return
                ob = bytes(jsonnized, "utf-8")
                if not response[0]:
                    self.scn_send_answer(400, body=ob, mime="application/json", docache=False)
                else:
                    self.scn_send_answer(200, body=ob, mime="application/json", docache=False)
        def do_POST(self):
            """ access to client_client and client_server """
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
            if resource == "wrap" and not nowrap:
                if not self.links["auth_server"].verify("server", self.auth_info):
                    authreq = self.links["auth_server"].request_auth()
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                else:
                    self.connection.settimeout(self.etablished_timeout)
                    self.handle_wrap(sub)
            elif resource == "usebroken":
                # for invalidating and updating, don't use connection afterwards
                self.handle_usebroken(sub)
            elif server and resource == "server":
                self.handle_server(sub)
            elif client and resource == "client":
                self.handle_client(sub)
            else:
                self.scn_send_answer(404, message="resource not found (POST)", docache=True)
            self.connection.settimeout(self.server_timeout)
    return client_handler

class client_init(object):
    config_root = None
    plugins_config = None
    links = None
    active = True
    pidpath = None

    @classmethod
    def create(cls, **kwargs):
        if not kwargs["nolock"]:
            pidpath = get_pidlock(kwargs["run"], "{}-simplescn-client.lck".format(os.getuid()))
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
        _cpath = os.path.join(self.links["config_root"], "client")
        init_config_folder(self.links["config_root"], "client")

        if not check_certs(_cpath + "_cert"):
            logging.info("Certificate(s) not found. Generate new...")
            generate_certs(_cpath + "_cert")
            logging.info("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip() #why fail
        #self.links["auth_client"] = scnauth_client()
        self.links["auth_server"] = scnauth_server(dhash(pub_cert))
        self.links["trusteddb"] = permissionhash_db(os.path.join(self.links["config_root"], "trusteddb.sqlite"))

        if bool(kwargs.get("spwhash")):
            if not check_hash(kwargs.get("spwhash")):
                logging.error("hashtest failed for spwhash, spwhash: %s", kwargs.get("spwhash"))
            else:
                self.links["auth_server"].init_realm("server", kwargs.get("spwhash"))
        elif bool(kwargs.get("spwfile")):
            with open(kwargs["spwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init_realm("server", dhash(pw))

        with open(_cpath+"_name.txt", 'r') as readclient:
            _name = readclient.readline().strip().rstrip() # remove \n
        with open(_cpath+"_message.txt", 'r') as readinmes:
            _message = readinmes.read()
        #report missing file
        if None in [pub_cert, _name, _message]:
            raise Exception("missing")
        _name = _name.split("/")
        if len(_name) > 2 or not check_name(_name[0]):
            logging.error("Configuration error in %s\nshould be: <name>/<port>\nor name contains some restricted characters", _cpath + "_name")
            sys.exit(1)
        if kwargs.get("port") > -1:
            port = kwargs.get("port")
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = config.client_port
        sslcont = default_sslcont()
        sslcont.load_cert_chain( _cpath+"_cert.pub", _cpath+"_cert.priv", lambda pwmsg: bytes(pwcallmethod("Enter server certificate pw"), "utf-8"))
        
        if kwargs.get("remote", False):
            self.links["shandler"] = gen_client_handler(self.links, kwargs.get("server_timeout"), kwargs.get("default_timeout"), server=True, client=True, remote=True, nowrap=kwargs.get("nowrap", False))
        else:
            self.links["shandler"] = gen_client_handler(self.links, kwargs.get("server_timeout"), kwargs.get("default_timeout"), server=True, client=False, remote=False, nowrap=kwargs.get("nowrap", False))
        self.links["hserver"] = http_server(("", port), sslcont, self.links["shandler"])
        
        if not kwargs.get("noip", False) or (not kwargs.get("nounix") and file_family):
            self.links["chandler"] = gen_client_handler(self.links, kwargs.get("server_timeout"), kwargs.get("default_timeout"), server=False, client=True, remote=False, nowrap=True)
            if file_family is not None:
                rpath = os.path.join(kwargs.get("run"), "{}-simplescn-client.unix".format(os.getuid()))
                self.links["cserver_unix"] = http_server(rpath, sslcont, self.links["chandler"], use_unix=True)
            if not kwargs.get("noip", False):
                self.links["cserver_ip"] = http_server(("::1", port), sslcont, self.links["chandler"])
                self.links["cserver_ip4"] = http_server(("::ffff:127.0.0.1", self.links["cserver_ip"].server_port), sslcont, self.links["chandler"])

        self.links["client"] = client_client(_name[0], dhash(pub_cert), self.links)
        clientserverdict = {"name": _name[0], "cert_hash": dhash(pub_cert),
                            "priority": kwargs.get("priority"), "message": _message, "links": self.links}

        self.links["client_server"] = client_server(clientserverdict)

        self.links["hserver"].serve_forever_nonblock()
        if "cserver_unix" in self.links:
            self.links["cserver_unix"].serve_forever_nonblock()
        if "cserver_ip" in self.links:
            self.links["cserver_ip"].serve_forever_nonblock()
        if "cserver_ip4" in self.links:
            self.links["cserver_ip4"].serve_forever_nonblock()


    def join(self):
        self.links["hserver"].serve_join()

    def quit(self):
        if not self.active:
            return
        self.active = False
        self.links["hserver"].server_close()
        if "client_ip" in self.links:
            self.links["client_ip"].server_close()
        if "client_unix" in self.links:
            self.links["client_unix"].server_close()

    def show(self):
        ret = dict()
        ret["cert_hash"] = self.links["client"].cert_hash
        _r = self.links["hserver"]
        ret["hserver"] = _r.server_name, _r.server_port
        _r = self.links.get("cserver_ip", None)
        if _r:
            ret["cserver_ip"] = _r.server_name, _r.server_port
        else:
            ret["cserver_ip"] = ret["hserver"]
        _r = self.links.get("cserver_unix", None)
        if _r:
            ret["cserver_unix"] = _r.server_name
        return ret

#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args = \
{
    "spwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than spw, lowercase"],
    "spwfile": ["", str, "<pw>: password file"],
    "remote" : ["False", parsebool, "<bool>: remote reachable (not only localhost) (needs cpwhash/file)"],
    "priority": [str(config.default_priority), int, "<int>: set client priority"],
    "connect_timeout": [str(config.connect_timeout), int, "<int>: set timeout for connecting"],
    "server_timeout": [str(config.server_timeout), int, "<int>: set timeout for servercomponent"],
    "timeout": [str(config.default_timeout), int, "<int>: set default timeout (etablished connections)"],
    "loglevel": [str(config.default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "port": [str(-1), int, "<int>: port of server component, -1: use port in \"client_name.txt\""],
    "config": [config.default_configdir, parsepath, "<dir>: path to config dir"],
    "run": [config.default_runpath, parsepath, "<dir>: path where unix socket and pid are saved"],
    "nounix": ["False", parsebool, "<bool>: deactivate unix socket client server"],
    "noip": ["False", parsebool, "<bool>: deactivate ip socket client server"],
    "trustforall": ["False", parsebool, "<bool>: everyone can access hashdb security"],
    "nolock": ["False", parsebool, "<bool>: disable pid lock"],
    "nowrap": ["False", parsebool, "<bool>: disable wrap"],
    "notraverse": ["False", parsebool, "<bool>: disable traversal"]
}

def client_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(default_client_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc
