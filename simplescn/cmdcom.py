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

from simplescn.scnrequest import do_request_simple

def cmdloop(ip, use_unix=False):
    while True:
        inp = input("Enter command:\n")
        kwargs = {}
        for elem in shlex.split(inp):
            splitted = elem.split("=", 1)
            if len(splitted) == 2:
                kwargs[splitted[0]] = splitted[1]
        command = kwargs.pop("command", "show")
        try:
            ret = do_request_simple(ip, "/client/{}".format(command), kwargs, use_unix=use_unix)
            print(ret)
        except Exception as exc:
            print(exc, file=sys.stderr)


def _single(argv, use_unix):
    if len(argv) >= 2:
        url = argv[1]
        command = argv[2]
        if len(argv) >= 3:
            stuff = argv[3]
        else:
            stuff = input()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        ret = do_request_simple(url, "/client/{}".format(command), stuff, headers, use_unix=use_unix)
        print(ret)
    else:
        print("Usage: single <url> <command>", file=sys.stderr)


def single(argv=sys.argv[1:]):
    _single(argv, False)

def single_unix(argv=sys.argv[1:]):
    _single(argv, True)


def _loop(argv, use_unix):
    if len(argv) >= 1:
        url = argv[0]
        cmdloop(url, use_unix)
    else:
        print("Usage: loop <url>", file=sys.stderr)

def loop(argv=sys.argv[1:]):
    _loop(argv, False)

def loop_unix(argv=sys.argv[1:]):
    _loop(argv, True)

def _test(argv, use_unix):
    from simplescn.__main__ import client, server, running_instances
    c = client(doreturn=True)
    running_instances.append(c)
    t = c.show()
    s = server(doreturn=True)
    running_instances.append(s)
    print("client ip", t.get("cserver_ip", None))
    print("client unix",  t.get("cserver_unix", None))
    print("client server", t.get("hserver", None))
    print("server", "::1-{}".format(s.links.get("hserver").server_port))
    if use_unix:
        cmdloop(t.get("cserver_unix"), use_unix=True)
    else:
        cmdloop("::1-{}".format(t.get("cserver_ip")[1]))

def test(argv=sys.argv[1:]):
    _test(argv, False)

def test_unix(argv=sys.argv[1:]):
    _test(argv, True)


def _init_method_main(argv=sys.argv[1:]):
    if len(argv) >= 1:
        toexe = globals().get(argv[0].strip("_"), None)
        if callable(toexe):
            toexe(argv[1:])
        else:
            print("Available: single, test, test_unix, loop", file=sys.stderr)
    else:
        print("Available: single, test, test_unix, loop", file=sys.stderr)

if __name__ == "__main__":
    _init_method_main()
