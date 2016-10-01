#! /usr/bin/env python3
"""
pwcallmethods
license: MIT, see LICENSE.txt
"""
from . import cmd


pwcallmethodinst = cmd.pwcallmethod
#def sel_pwcallmethodinst(modulename):
#    global pwcallmethodinst
#    try:
#        module = importlib.import_module(modulename)
#        pwcallmethodinst = module.pwcallmethod
#        return True
#    except ImportError:
#        return False



#sel_pwcallmethodinst("pwcallmethod.cmd")



# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)
