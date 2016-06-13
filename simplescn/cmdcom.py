#! /usr/bin/env python3
"""
communication interface
license: MIT, see LICENSE.txt
"""
import shlex
import sys
import os

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(sys.modules[__name__].__file__))
    _tpath = os.path.dirname(_tpath)
    sys.path.insert(0, _tpath)


from simplescn.scnrequest import do_request_mold
from simplescn.__main__ import client, server, running_instances

def cmdloop(ip):
    while True:
        inp = input("Enter command:\n")
        kwargs = {}
        for elem in shlex.split(inp):
            splitted = elem.split("=", 1)
            if len(splitted) == 2:
                kwargs[splitted[0]] = splitted[1]
        command = kwargs.pop("command", "show")
        try:
            ret = do_request_mold(ip, "/client/{}".format(command), kwargs)
            print(ret)
        except Exception as e:
            print(e)

def init_method_main(argv=sys.argv[1:]):
    if len(argv) >= 1:
        toexe = globals().get(argv[0])
        if callable(toexe):
            toexe(sys.argv[1:])
    else:
        print("Usage: {} [single, test, loop]".format(sys.argv[0]), file=sys.stderr)

def single(argv=sys.argv[1:]):
    if len(argv) >= 2:
        url = argv[1]
        command = argv[2]
        if len(argv) >= 3:
            stuff = argv[3]
        else:
            stuff = input()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        print(do_request_mold(url, "/client/{}".format(command), stuff, headers))
    else:
        print("Usage: {} single <url> <command>".format(sys.argv[0]), file=sys.stderr)

def loop(argv=sys.argv[1:]):
    if len(argv) >= 1:
        url = argv[1]
        cmdloop(url)
    else:
        print("Usage: {} loop <url>".format(sys.argv[0]), file=sys.stderr)

def test(argv=sys.argv[1:]):
    c = client(doreturn=True)
    running_instances.append(c)
    t = c.show()
    s = server(doreturn=True)
    running_instances.append(s)
    print("client ip", t.get("cserver_ip", None))
    print("client unix",  t.get("cserver_unix", None))
    print("client server", t.get("hserver", None))
    print("server", "::1-{}".format(s.links.get("hserver").server_port))
    cmdloop("::1-{}".format(t.get("cserver_ip")[1]))


if __name__ == "__main__":
    init_method_main()
