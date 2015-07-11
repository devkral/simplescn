Simple replacement for dyndns.
Just register your clients with their own new generated keys
nodes are not permanent, a restart deletes the entries on the server

Features:
* passwordprotection
* entirely controllable by webbrowser

Dependencies:
* python-openssl (python3 version)
* python-gobject (python3 version)
* gtk3
* python3


This is a rewrite of scn.
It got too complex because of unnecessary features (channels and nodes), too much lowlevel work (an own protocol), focus on gui and a client and serverside account management.


