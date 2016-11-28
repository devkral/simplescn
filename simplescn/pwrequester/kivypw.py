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

def pwcallmethod(msg):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    with subprocess.Popen([sys.executable, __file__], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate(bytes(msg, "utf-8"))[0][:-1], "utf-8")

if __name__ == "__main__":
    from kivy.app import App
    #from kivy.core.window import Window
    from kivy.uix.floatlayout import FloatLayout

    from kivy.config import Config
    Config.set('kivy', "exit_on_escape", 0)
    Config.set('graphics', 'width', '400')
    Config.set('graphics', 'height', '400')
    Config.set('graphics', 'borderless', '1')

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
            self.title = "Password request"
            ret = PwDialog()
            ret.ids["msglabel"].text = self.msg
            return ret

    app = KivyPwApp(input())
    app.run()
    sys.exit(0)
