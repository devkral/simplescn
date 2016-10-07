
"""
config
public domain (only options)
"""
import tempfile
import os
from cryptography.hazmat.primitives import hashes

logformat = '%(levelname)s::%(filename)s:%(lineno)d::%(funcName)s::%(message)s'

# debug mode (activates server stacktraces)
debug_mode = "SCNDEBUG" in os.environ
# all transmitted error messages are unknown
harden_mode = False

## sizes ##
salt_size = 10
token_size = 10
key_size = 4096
# size of chunks (only in use by rw_socket?)
default_buffer_size = 1400
max_serverrequest_size = 4000
# maybe a bad idea to change
max_typelength = 15
max_namelength = 64
max_urllength = 400
# default cache size
default_cache_size = 256

## dbending
dbending = ".sqlite"

## password prompts:
pwcertgen_prompt = "(optional) Enter passphrase for encrypting key"
pwrealm_prompt = "Please enter password"
pwdecrypt_prompt = "Please enter password to unlock key"
hashpw_prompt = "Please enter password or generate with: 'random' a random pw: "

## can be None (auto select), False (no), "sortedcontainers", "blist"
use_sorteddict = None

## timeouts ##
# time out for auth requests
auth_request_expire_time = 60*3
ping_interval = 50
# timeouts for connecting and else
default_timeout = 60
connect_timeout = 5
server_timeout = 20
traverse_retries = 3
# url to ipv6 caching time to live (possibly not used)
urlttl = 30

## file positions ##
default_configdir = '$HOME/.simplescn'
default_runpath = tempfile.gettempdir()
# don't change
isself = 'isself'

## ports ##
client_port = 0 # 0 = random port, recommended
server_port = 4040 # fixed server port

## defaults ##
default_priority = 20
default_loglevel = "DEBUG"

## hash algorithms ##
algorithms_strong = ['sha512', 'sha384', 'sha256', 'whirlpool']
validhexhashlengths = [64,  96, 128]
cert_sign_hash = hashes.SHA512()
# don't change
DEFAULT_HASHALGORITHM = "sha256"
security_states = ["compromised", "old", "valid", "insecure"]

## server only ##

# loads: min_items, refresh, expire
high_load = (100000, 10*60, 2*60*60)
medium_load = (1000, 60, 4*60*60)
low_load = (500, 10, 4*60*60)
# special load just: refresh, expire
very_low_load = (1, 24*60*60)
