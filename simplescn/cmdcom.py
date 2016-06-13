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


from simplescn.scnrequest import do_request
from simplescn.__main__ import client

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
            ret = do_request(ip, "/client/{}".format(command), **kwargs)
            print(ret)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    c = client(doreturn=True)
    t = c.show()
    print("::1-{}".format(t.get("cserver_ip").server_port))
    cmdloop("::1-{}".format(t.get("cserver_ip").server_port))
