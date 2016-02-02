#! /usr/bin/env python3

#license: bsd3, see LICENSE.txt
"""
startscript for simplescn
"""
import sys

# load for nuitkabuild also a good test if available
try:
    import markdown
except ImportError:
    print("No markdown support", file=sys.stderr)

try:
    import gi
except ImportError:
    print("No gtk gui support", file=sys.stderr)

# required:
try:
    import cryptography
except ImportError:
    print("Error: no cryptography", file=sys.stderr)
    sys.exit(1)
from simplescn import __main__
if __name__ == "__main__":
    __main__.init_method_main()
