#! /usr/bin/env python3

"""
import from different client
license: MIT, see LICENSE.txt
"""

import sys
import os

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(__file__))
    _tpath = os.path.dirname(_tpath)
    if _tpath not in sys.path:
        sys.path.insert(0, _tpath)

from simplescn import config
from simplescn.scnrequest import do_request, pwcallmethod_realm
from simplescn._common import scnparse_args, parsepath

def massparse(inp):
    if inp == "":
        return None
    return inp.split(";")

def massimport(con_or_addr, sourceaddr, sourcehash, listentities=None, listhashes=None, forcehash=None, pwhandler=None):
    body = {"sourceaddr": sourceaddr, "sourcehash": sourcehash, "listentities": listentities, "listhashes": listhashes}
    ret = do_request(con_or_addr, "/client/massimport", body, pwhandler=pwhandler, forcehash=forcehash)
    ret[0].close()
    return ret[1:]

def _getclientcon(addr, configdir=config.default_configdir, forcehash=None):
    if addr == "":
        from simplescn.__main__ import client, running_instances
        c = client(["nounix=True", "port=0", "nopid=True", "config={}".format(configdir)], doreturn=True)
        running_instances.append(c)
        addr = c.show()["cserver_ip"]
        _hash = c.show()["cert_hash"]
    else:
        _hash = None
    ret = do_request(addr, "/client/show", {}, pwhandler=pwcallmethod_realm, forcehash=_hash)
    if not ret[0] or not ret[1]:
        raise(Exception("Invalid client"))
    return ret[0], ret[2]

def cmdmassimport(argv=sys.argv[1:]):
    kwargs = scnparse_args(argv, massimport_paramhelp, massimport_args)
    _hash = kwargs.get("forcehash")
    saddr = kwargs.get("sourceaddress")
    if not bool(saddr):
        print("Error: no sourceaddress", file=sys.stderr)
        return

    shash = kwargs.get("sourcehash")
    if not bool(shash):
        print("Error: no sourcehash", file=sys.stderr)
        return
    con_or_addr, _hash = _getclientcon(kwargs["address"], kwargs["config"], forcehash=_hash)
    ret = massimport(con_or_addr, saddr, shash, kwargs["listentities"], \
        kwargs["listhashes"], pwhandler=pwcallmethod_realm, forcehash=_hash)
    print(ret)

massimport_args = \
{
#    "cpwhash": ["", str, "<lowercase hash>: sha256 hash of pw for auth"],
#    "cpwfile": ["", str, "<pw>: password file (needed for remote control)"],
    "forcehash": ["", str, "<lowercase hash>: hash of client"],
    "address": ["", str, "<lowercase hash>: address of target client (copied to)"],
    "sourceaddr": ["", str, "<lowercase hash>: address of source client"],
    "sourcehash": ["", str, "<lowercase hash>: hash of source client"],
    "listentities": ["", massparse, "<name>; <name2>; ...: entity names, seperated by ; empty for all"],
    "listhashes": ["", massparse, "<hash1>; <hash2>; ...: hashes by ; empty for all"],
    "config": [config.default_configdir, parsepath, "<dir>: path to config dir"]
}

def massimport_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(massimport_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc

if __name__ == "__main__":
    cmdmassimport()
