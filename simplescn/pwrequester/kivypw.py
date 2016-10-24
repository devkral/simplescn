#! /usr/bin/env python3
"""
dialogs for kivy gui
license: MIT, see LICENSE.txt
"""

import os
import sys
import subprocess
import logging

basedir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

import kivy
kivy.require('1.9.1')
from kivy.app import App
#from kivy.core.window import Window
from kivy.uix.floatlayout import FloatLayout

class PwDialog(FloatLayout):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        #self.ids["msg"] = msg

    def ok(self):
        print(self.ids["pwfield"].text)
        App.get_running_app().stop()
    def cancel(self):
        print("")
        App.get_running_app().stop()

class KivyPwApp(App):
    """ func: kivy password dialog
        return: "" or pw
    """
    msg = None
    def __init__(self, msg):
        self.msg = msg
        super().__init__()

    def build(self):
        self.icon = os.path.join(basedir, "icon.svg")
        ret = PwDialog()
        ret.ids["msglabel"].text = self.msg
        return ret


def pwcallmethod(msg):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    with subprocess.Popen([sys.executable, __file__, msg], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate()[0][:-1], "utf-8")

if __name__ == "__main__":
    app = KivyPwApp(sys.argv[1])
    app.run()
    sys.exit(0)
