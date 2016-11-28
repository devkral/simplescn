#! /usr/bin/env python3
"""
dialogs for qt gui
license: MIT, see LICENSE.txt
"""

import os
import sys
import subprocess
import logging

import PyQt5

def pwcallmethod(msg):
    if sys.executable in ["", None]:
        logging.error("Cannot open interpreter for subprocess")
        return ""
    with subprocess.Popen([sys.executable, __file__], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        return str(proc.communicate(bytes(msg, "utf-8"))[0][:-1], "utf-8")

if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication, QInputDialog, QLineEdit

    def _qt_pw(msg):
        """ func: qt password dialog
            return: "" or pw
        """
        app = QApplication(sys.argv)
        d = QInputDialog()
        d.setTextEchoMode(QLineEdit.Password)
        d.setLabelText(msg)
        if d.exec() == 0:
            return ""
        return d.textValue()
    print(_qt_pw(input()))
    sys.exit(0)
