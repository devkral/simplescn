#! /usr/bin/env python3

"""
main starter
license: MIT, see LICENSE.txt
"""

try:
    # . for not loading different module
    from . import cmdmassimport
except (ImportError, SystemError):
    import sys
    import os
    # don't load different module
    ownpath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    sys.path.insert(0, os.path.dirname(ownpath))
    from simplescn.massimport import cmdmassimport

cmdmassimport()
