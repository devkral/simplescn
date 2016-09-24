#! /usr/bin/env python3
"""
communication interface
license: MIT, see LICENSE.txt
"""
import shlex
import sys
import os
import socket
import threading

# don't load different module
if __name__ == "__main__":
    ownpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, os.path.dirname(ownpath))

from simplescn import pwcallmethod
from simplescn.scnrequest import do_request_simple, do_request
from simplescn.tools import getlocalclient, rw_socket
from simplescn.tools.checks import check_local

def cmdloop(ip, use_unix=False, forcehash=None):
    while True:
        inp = input("Enter action:\n")
        body = {}
        for elem in shlex.split(inp):
            splitted = elem.split("=", 1)
            if len(splitted) == 2:
                body[splitted[0]] = splitted[1]
        action = body.pop("action", "show")
        #try:
        ret = do_request_simple(ip, "/client/{}".format(action), body, {}, pwhandler=pwcallmethod, use_unix=use_unix, forcehash=forcehash, ownhash=forcehash)
        if "origcertinfo" in ret[1]:
            del ret[1]["origcertinfo"]
        print(ret)
        #except Exception as exc:
        #    print(exc, file=sys.stderr)


def _single(address, use_unix, argv):
    command = argv[1]
    if len(argv) >= 2:
        stuff = argv[2]
    else:
        stuff = input()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    ret = do_request_simple(address, "/client/{}".format(command), stuff, headers, use_unix=use_unix)
    print(ret)


def single(argv=sys.argv[1:]):
    if len(argv) < 1:
        print("Usage: single <command>", file=sys.stderr)
        return
    ret = getlocalclient()
    if ret:
        _single(ret[0], ret[1], argv)
    else:
        print("Error: client is not active or uses different run-directory", file=sys.stderr)

def single_ip(argv=sys.argv[1:]):
    if len(argv) < 2:
        print("Usage: single_ip <url> <command>", file=sys.stderr)
    else:
        _single(argv[0], False, argv[1:])

def single_unix(argv=sys.argv[1:]):
    if len(argv) < 2:
        print("Usage: single_ip <path> <command>", file=sys.stderr)
    else:
        _single(argv[0], True, argv[1:])

def loop(argv=sys.argv[1:]):
    ret = getlocalclient()
    if ret:
        cmdloop(*ret)
    else:
        print("Error: client is not active or uses different run-directory", file=sys.stderr)

def loop_ip(argv=sys.argv[1:]):
    if len(argv) < 1:
        print("Usage: loop_ip <url>", file=sys.stderr)
    else:
        cmdloop(argv[0], False)

def loop_unix(argv=sys.argv[1:]):
    if len(argv) < 2:
        print("Usage: loop_unix <path>", file=sys.stderr)
    else:
        cmdloop(argv[0], True)

def _test(argv, use_unix):
    from simplescn.tools.start import client, server, running_instances
    aargv = argv.copy()
    if use_unix:
        aargv.append("--nounix=False")
    else:
        aargv.append("--noip=False")
    c = client(aargv, doreturn=True)
    running_instances.append(c)
    if not c:
        print("Client could not start (maybe other instance)")
        return
    t = c.show()
    s = server(["--nolock=True", "--port=0"], doreturn=True)
    if not s:
        print("Server could not start")
        return
    t2 = s.show()
    running_instances.append(s)
    print("client ip", t.get("cserver_ip", None),  sep=":\t")
    print("client unix", t.get("cserver_unix", None),  sep=":\t")
    print("client server", t.get("hserver"),  sep=":\t")
    print("client hash", t.get("cert_hash"),  sep=":\t")
    print("server", "::1-{}".format(t2["hserver"][1]),  sep=":\t\t")
    print("server hash", t2.get("cert_hash"),  sep=":\t")
    if use_unix:
        cmdloop(t.get("cserver_unix"), use_unix=True, forcehash=t.get("cert_hash"))
    else:
        cmdloop("::1-{}".format(t.get("cserver_ip")[1]), forcehash=t.get("cert_hash"))

def test_ip(argv=sys.argv[1:]):
    _test(argv, False)

def test_unix(argv=sys.argv[1:]):
    _test(argv, True)

def direct_proxy(argv=sys.argv[1:]):
    server = None
    traverseserver = None
    name = None
    certhash = None
    address = None
    port = 0
    if len(argv) == 2:
        address, service = argv
    elif len(argv) == 3:
        address, service, port = argv
    elif len(argv) == 4:
        server, name, certhash, service = argv
    elif len(argv) == 5:
        server, name, certhash, service, port = argv
    else:
        print("Usage: direct_proxy (address service [port])/(server name certhash service [port])", file=sys.stderr)
        return
    if not address:
        bodyserver = {"name": name, "hash": certhash}
        ret = do_request_simple(server, "/server/get", bodyserver, {})
        if ret[1]:
            address = ret[2].get("address", None)
            if ret[2].get("traverse_needed", False):
                traverseserver = server

    if not address:
        print("Could not retrieve address", file=sys.stderr)
        return
    localcl_ret = getlocalclient()
    body_lwrap = {"name": service, "address": address}
    if traverseserver:
        body_lwrap["traverseaddress"] = traverseserver
    soc = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    soc.bind(("", port))
    print('{"port": %s}' % soc.getsockname()[1])
    soc.listen()
    while True:
        conn, addr = soc.accept()
        if not check_local(addr[0]):
            print("SKIP: not local address {}".format(addr), file=sys.stderr)
            conn.close()
            continue
        if localcl_ret:
            ret_proxy = do_request(localcl_ret[0], "/client/wrap", body_lwrap, {}, \
                                   forcehash=certhash, keepalive=True, use_unix=localcl_ret[1])
        else:
            ret_proxy = do_request(address, "/wrap/{}".format(service), {}, {}, traverseaddress=traverseserver, \
                                   forcehash=certhash, keepalive=True)
        if not ret_proxy[1] or not ret_proxy[0]:
            print("Could not wrap: {}".format(ret_proxy[2]), file=sys.stderr)
            conn.close()
            continue
        wrapsoc = ret_proxy[0].sock
        ret_proxy[0].sock = None
        threading.Thread(target=rw_socket, args=(conn, wrapsoc), daemon=True).start()

def _init_method_main(argv=sys.argv[1:]):
    if len(argv) >= 1:
        toexe = globals().get(argv[0].strip("_"), None)
        if callable(toexe):
            toexe(argv[1:])
        else:
            print("Available: single{_ip, _unix, -}, loop{_ip, _unix, -}, test{_ip, _unix}}, direct_proxy", file=sys.stderr)
    else:
        print("Available: single{_ip, _unix, -}, loop{_ip, _unix, -}, test{_ip, _unix}}, direct_proxy", file=sys.stderr)

if __name__ == "__main__":
    _init_method_main()
