#! /usr/bin/env python3

import socket
import time
import ssl
from http.client import HTTPConnection, HTTPResponse, _CS_IDLE, HTTPException


def unix_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    address = address[0]
    err = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock

    except HTTPException as exc:
        err = exc
        if sock is not None:
            sock.close()

    if err is not None:
        raise err
    else:
        raise HTTPException("getaddrinfo returns an empty list")
    
class SCNConnection(HTTPConnection):

    def __init__(self, host, port=None,
                     timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                     source_address=None, *, context=None, plaintext=False):
        super(SCNConnection, self).__init__(host, port, timeout,
                                                  source_address)
        self.plaintext = plaintext

        if not port: # use unix connection instead
            self.host, self.port = host, None
            self._create_connection = unix_create_connection
        if not self.plaintext:
            if context is None:
                context = ssl._create_default_https_context()
            self._context = context

    def connect(self):
        "Connect to a host on a given (SSL) port."
        
        super().connect()

        if not self.plaintext:
            if self._tunnel_host:
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host
            # stop if plaintext
            self.sock = self._context.wrap_socket(self.sock,
                                                  server_hostname=server_hostname)

con = SCNConnection('./willi', plaintext=True)
con.request("GET", "/path")
ret = con.getresponse()
if ret.status != 200:
    print("error", ret.status)
else:
    print("success", ret.read())
