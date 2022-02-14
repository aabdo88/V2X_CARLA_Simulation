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
from enrollment_helper import *
from optparse import OptionParser

parser=OptionParser()
parser.add_option("-p", "--privKeyRecon", dest="privKeyRecon", help="Provate key rescontruction value", metavar="PRIRECON")
parser.add_option("-t", "--enrollmentCertTbs", dest="enrollmentCertTbs", help="Enrollment cert TBS data", metavar="ENROLLTBS")
parser.add_option("-e", "--ecaCert", dest="ecaCert", help="ECA certificate", metavar="ECACERT")
parser.add_option("-b", "--basePrivateKey", dest="basePrivateKey", help="Base private key", metavar="BASEPRIV")
(options,args)=parser.parse_args()

cert_digest = create1609Dot2Digest(options.enrollmentCertTbs, options.ecaCert)[0]
enroll_private_key = reconstructPrivateKey(options.basePrivateKey, cert_digest, options.privKeyRecon, sec4=False, cert_dgst=True)

print(enroll_private_key)

def keyGen() :
    # compute an ECC keypair for the request
    prv_long = randint(1, genP256.ecc.n-1)
    reqPrv = "{0:0>{width}X}".format(prv_long, width=bitLen(genP256.ecc.n)*2/8)
    reqPub = prv_long*genP256
    return (reqPrv, reqPub)

# create butterfly keys
verifyKeyPriv, verifyKeyPub = keyGen()
print(verifyKeyPriv)
print(str(verifyKeyPub.output(compress=True, Ieee1609Dot2=True)))
respEncPriv, respEncKeyPub = keyGen()
print(respEncPriv)
print(str(respEncKeyPub.output(compress=True, Ieee1609Dot2=True)))
