#! /usr/bin/env python3

"""
load parameters, stuff
license: MIT, see LICENSE.txt
"""

import os
import sys
from getpass import getpass


sharedir = os.path.dirname(os.path.realpath(__file__))
# append to pathes
if sharedir not in sys.path:
    sys.path.insert(0, sharedir)

#__all__ = ["simplescn.tools", "AuthNeeded", "AddressFail"]
#__all__ += ["EnforcedPortFail", "AddressEmptyFail", "AddressInvalidFail"]
#__all__ += ["InvalidLoadError"]
#__all__ += ["VALError", "VALNameError", "VALHashError", "VALMITMError"]
#__all__ += ["pwcallmethodinst", "pwcallmethodinst", "resp_st"]

###### signaling ######

class AuthNeeded(Exception):
    reqob = None
    con = None
    def __init__(self, con, reqob):
        self.reqob = reqob
        self.con = con

class AddressFail(Exception):
    msg = ''
    basemsg = '<address>[-<port>]:\n'
    def __str__(self):
        return self.basemsg + self.msg

class EnforcedPortFail(AddressFail):
    msg = 'address is lacking -<port>'
class AddressEmptyFail(AddressFail):
    msg = 'address is empty'
class AddressInvalidFail(AddressFail):
    msg = 'address is invalid'

class InvalidLoadError(Exception):
    msg = ''
    def __str__(self):
        return self.msg
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load is invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
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

resp_st = \
{
    "status":"", # ok/error
    "result": None,
    "error": None
}



def inp_passw_cmd(msg):
    return getpass(msg+":\n")
pwcallmethodinst = inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)

