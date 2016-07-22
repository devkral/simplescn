#! /usr/bin/env python3

"""
import from different client
license: MIT, see LICENSE.txt
"""

import sys
import os

# don't load different module
if __name__ == "__main__":
    ownpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, os.path.dirname(ownpath))

from simplescn import config, pwcallmethod
from simplescn._common import scnparse_args, parsepath

def massparse(inp):
    if inp == "":
        return None
    return inp.split(";")

def manageperms(kwargs):
    _hash = kwargs.get("hash")
    _action = kwargs.get("action")
    _perms = kwargs.get("hash")
    _permissions = kwargs.get("permissions")


def cmdmanageperms(argv=sys.argv[1:]):
    kwargs = scnparse_args(argv, manageperms_paramhelp, manageperms_args)
    print(manageperms(kwargs))

manageperms_args = \
{
    #"cpwhash": ["", str, "<lowercase hash>: sha256 hash of pw for auth"],
    #"cpwfile": ["", str, "<pw>: password file (needed for remote control)"],
    "hash": ["", str, "<lowercase hash>: hash of client"],
    "action": ["", str, "<add,del,get> action"],
    "permissions": ["", str, "<lowercase hash>: address of source client"],
    "config": [config.default_configdir, parsepath, "<dir>: path to config dir"]
}

def manageperms_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(manageperms_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc

if __name__ == "__main__":
    cmdmassimport()
