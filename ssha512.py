#!/usr/bin/python2

import hashlib
import os
import sys
from base64 import b64encode

def ssha512(password):
  salt = os.urandom(4)
  h = hashlib.sha512(password)
  h.update(salt)
  return b64encode(h.digest() + salt)

print (ssha512(sys.argv[1]))
