#! /usr/bin/env python3
"""
load parameters, stuff
license: MIT, see LICENSE.txt
"""
import sys
import os


#__all__ = ["simplescn.tools", "AuthNeeded", "AddressError"]
#__all__ += ["EnforcedPortError", "AddressEmptyError", "AddressInvalidError"]
#__all__ += ["InvalidLoadError"]
#__all__ += ["VALError", "VALNameError", "VALHashError", "VALMITMError"]
#__all__ += ["pwcallmethodinst", "pwcallmethodinst", "resp_st"]

###### encode pw ######
def hashpw(argv=sys.argv[1:]):
    """ create pw hash for *pwhash """
    from simplescn.tools import dhash
    import base64
    if len(sys.argv) < 2 or sys.argv[1] in ["--help", "help"]:
        print("Usage: {} hashpw <pw>/\"random\"".format(sys.argv[0]))
        return
    pw = argv[0]
    if pw == "random":
        pw = str(base64.urlsafe_b64encode(os.urandom(10)), "utf-8")
    print("pw: {}, hash: {}".format(pw, dhash(pw)))
###### signaling ######

class AuthNeeded(Exception):
    reqob = None
    con = None
    def __init__(self, con, reqob):
        super().__init__()
        self.reqob = reqob
        self.con = con

class AddressError(Exception):
    msg = ''
    basemsg = '<address>[-<port>]:\n'
    def __str__(self):
        return self.basemsg + self.msg

class EnforcedPortError(AddressError):
    msg = 'address lacking -<port>'
class AddressEmptyError(AddressError):
    msg = 'address empty'
class AddressLengthError(AddressError):
    msg = 'address too long'
class AddressInvalidError(AddressError):
    msg = 'address invalid'

class InvalidLoadError(Exception):
    msg = ''
    def __str__(self):
        return self.msg
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
class InvalidLoadLevelError(InvalidLoadError):
    msg = 'Load levels invalid (not high_load>medium_load>low_load)'

class VALError(Exception):
    msg = ''
    basemsg = 'validation failed:\n'
    def __str__(self):
        return self.basemsg + self.msg
class VALNameError(VALError):
    msg = 'Name spoofed/does not match'
class VALHashError(VALError):
    msg = 'Hash does not match'
class VALMITMError(VALError):
    msg = 'MITM-attack suspected: nonce missing or check failed'

def inp_passw_cmd(msg):
    from getpass import getpass
    return getpass(msg+":\n")
pwcallmethodinst = inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)
