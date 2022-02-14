#  (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# 
'''
Decrypt data generically
'''
from __future__ import print_function
import binascii
from optparse import OptionParser
parser=OptionParser()
parser.add_option("-y", "--yPoint", dest="yPoint",help="compressed y point to use, 0 or 1", metavar="YPT")
parser.add_option("", "--yValue", dest="yValue", help="the yValue data", metavar="YVAL")
parser.add_option("-c", "--cValue", dest="c", help="the encrypted symmetric key", metavar="CVAL")
parser.add_option("-t", "--tValue", dest="t", help="the authentication tag", metavar="TVAL")
parser.add_option("-n", "--nonce", dest="nonce", help="AES nonce", metavar="NONCE")
parser.add_option("", "--certificate", dest="certificate", help="Certificate data", metavar="CERTIFICATE")
parser.add_option("", "--ciphertext", dest="ciphertext", help="AES ciphertext", metavar="CIPHER")
parser.add_option("-p", "--privatekey", dest="privateKey", help="Private key data", metavar="PRIVKEY")

(options,args)=parser.parse_args()
from ecc import *
from implicit import *
from pkencrypt import *

# NOTE: make sure v is set to the correct point type (y-0 / y-1)
v = ECPoint("compressed-y-"+options.yPoint,options.yValue)

# decrypt the ciphertext using the encrypted key
ptxt = PKDecrypt(v, options.c, options.t, options.certificate, options.privateKey, options.nonce, options.ciphertext)

print(ptxt.upper())
