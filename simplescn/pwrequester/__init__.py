#! /usr/bin/env python3
"""
pwcallmethods
license: MIT, see LICENSE.txt
"""
import importlib
pwcallmethodinst = None
def sel_pwcallmethodinst(modulename):
    global pwcallmethodinst
    try:
        module = importlib.import_module(modulename, "simplescn.pwrequester")
        pwcallmethodinst = module.pwcallmethod
        return True
    except ImportError:
        return False

def init():
    if sel_pwcallmethodinst(".qtpw"):
        return
    if sel_pwcallmethodinst(".gtkpw"):
        return
    if sel_pwcallmethodinst(".kivypw"):
        return
    if sel_pwcallmethodinst(".cmdpw"):
        return

init()

# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)
