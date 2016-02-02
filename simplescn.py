#! /usr/bin/env python3

#license: bsd3, see LICENSE.txt
"""
startscript for simplescn
"""

from simplescn import __main__
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    __main__.init_method_main()
