#! /usr/bin/env python3

#license: bsd3, see LICENSE.txt
"""
startscript for simplescn
"""

# load for nuitkabuild
try:
    import markdown
except ImportError:
    pass

try:
    import gi
except ImportError:
    pass

from simplescn import __main__
if __name__ == "__main__":
    __main__.init_method_main()
