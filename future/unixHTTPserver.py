#! /usr/bin/env python3

import socket
import os
from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn,TCPServer

class UnixServer(TCPServer):
    
    address_family = socket.AF_UNIX
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        try:
            os.unlink(server_address)
        except OSError:
            if os.path.exists(server_address):
                raise
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=True)

    def get_request(self):
        con, addr = self.socket.accept()
        print(con)
        return con, ('', 0)

class ThreadingUnixServer(ThreadingMixIn, UnixServer):
    pass


class testBaseHTTPRequestHandler(SimpleHTTPRequestHandler):
    
    
    def do_GET(self):
        sendb = bytes("<html><body>own socket: {}<br/>peer socket: {}</body></html>".format(self.connection.getsockname(),self.connection.getpeername()), "utf-8")
        self.send_response(200)
        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Length", str(len(sendb)))
        self.end_headers()
        self.wfile.write(sendb)

if __name__ == "__main__":
    serv = ThreadingUnixServer("./willi",testBaseHTTPRequestHandler)
    serv.serve_forever()
