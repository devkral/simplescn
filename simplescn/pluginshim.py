#! /usr/bin/env python3

import sys
import json
import os
import socket
import logging

class pluginshim(object):
    portcom = None
    portpoll = None
    config = None

    def __init__(self, portcom, portpoll, plugin_config_path):
        self.portcom = portcom
        self.portpoll = portpoll
        self.plugin_config_path = plugin_config_path
    
    def loop(self, module):
        while True:
            command, args, kwargs = json.loads(input())
            try:
                print(json.dumps(getattr(module, command)(*args, **kwargs)))
            except Exception as exc:
                st = str(exc)
                if hasattr(exc, "__traceback__"):
                    st += "\n\n{}".format("".join(traceback.format_tb(exc.__traceback__)).replace("\\n", ""))
                print(False, e, file=sys.stderr)

if __name__ == "__main__":
    path, name, _portcom, _portpoll, plugin_config_path = sys.argv[1:]
    portcom = int(_portcom)
    portpoll = int(_portpoll)
    sys.modules["simplescn_plugins"] = pluginshim(_portcom, _portpoll, plugin_config_path)
    sys.path[0] = os.path.join(path, name)
    try:
        import __init__
    except Exception as exc:
        st = "..{}".format(exc)
        if hasattr(exc, "__traceback__"):
            st += "\n\n{}".format("".join(traceback.format_tb(exc.__traceback__)).replace("\\n", ""))
        print(st)
        sys.exit(1)
    print('ok')
    sys.modules["simplescn_plugins"].loop(__init__)
