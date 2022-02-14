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
from __future__ import print_function
import binascii
import time
import re

from bsmsign import *

# 1609.2 epoch in seconds
epoch1609Dot2 = 1072915200

# Read BSMs of OBU-1
bsmpath = "encodedData/BasicSafetyMessage"
## BSM1_1
bsm_in = open(bsmpath+"1-1.uper", "rb")
bsm1_1 = binascii.hexlify(bsm_in.read())
bsm_in.close()
print("bsm1_1 = " + bsm1_1.upper())
# 1135ea9b8d30ce5ad611ccd4c4e1fbc691246439afd19105c98dd50ad9f5ca9b03cc4dd000

signedbsm = ""
signedbsm += "038100"

bsm_tbs = "400380"
bsm_tbs += long2hexstr(len(bsm1_1)/2,8)
bsm_tbs += bsm1_1

# headerInfo with psid = 0 and generation time
bsm_tbs += "40"
# psid = 0
bsm_tbs += "0100"
# generationTime:
## On Monday July 10 at 10:22 EDT:
## long(time.time()) = 1499700131
## instead we'll use Tue, 11 Jul 2017 09:03:20 GMT (05:03:20 GMT-0400 (EDT))
currTime = 1499763800
generationTime = (currTime -  - epoch1609Dot2) * (10**6)
print("generationTime = " + str(generationTime).upper())
bsm_tbs += long2hexstr(generationTime,64).lower()
print("bsm_tbs = " + bsm_tbs.upper())

obu_path = "encodedData/25155fde3fd783a3/"

# Read in pca cert
pca_path = obu_path + "trustedcerts/pca"
pca_in = open(pca_path, "rb")
pca_cert = binascii.hexlify(pca_in.read())
pca_in.close()
## ensure the pca cert didn't change and contains
## the public key in this file
pca_key_pattern = re.compile('.+7c5c5ad2e441.+')
if not pca_key_pattern.match(pca_cert):  #if "7c5c5ad2e441" not in pca_cert:
    raise Exception("pca cert changed: it no longer matches the public key on file")
pca_pub_x = """                       7c 5c5a d2e4 4129
 9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
 dd9e 8e39 188f a57f ef
 """.replace("\n","").replace(" ", "")
pca_pub = ECPoint("compressed-y-0", pca_pub_x)

# Tuesday, July 11 at 5am EDT will start week 0x83
pseudo_cert_path = obu_path + "download/" + "83" + "/" + "83"
pseudo_cert_in = open(pseudo_cert_path + "_0.cert", "rb")
pseudo_cert1 = binascii.hexlify(pseudo_cert_in.read())
pseudo_cert_in.close()

prv_recon_in = open(pseudo_cert_path + "_0.s", "rb")
prv_recon1 = binascii.hexlify(prv_recon_in.read())
prv_recon_in.close()

pseudo_cert = pseudo_cert1
prv_recon = prv_recon1

# pseudo_cert_tbs extracted from the pseudo_cert
pseudo_cert_tbs = pseudo_cert[24:]

# verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
#
pub_recon_x = pseudo_cert_tbs[-64:]
# Import the key as an ECPoint
# Check if the reconstruction point is compressed-y-0 or compressed-y-1
if (pseudo_cert_tbs[-66:-64] == "82"):
    pub_recon = ECPoint("compressed-y-0", pub_recon_x)
else: #"83"
    pub_recon = ECPoint("compressed-y-1", pub_recon_x)

#OBU/25155fde3fd783a3/dwnl_sgn.priv
cert_seed_in=open(obu_path + "dwnl_sgn.priv","rb")
cert_seed_prv = binascii.hexlify(cert_seed_in.read())
cert_seed_in.close()

# OBU/25155fde3fd783a3/sgn_expnsn.key
cert_exp_in=open(obu_path + "/sgn_expnsn.key","rb")
cert_exp_val =binascii.hexlify(cert_exp_in.read())
cert_exp_in.close()

#Butterfly-expand and reconstruct a key pair corresponding to cert
pseudo_prv, pseudo_pub = BFExpandAndReconstructKey(
    cert_seed_prv, cert_exp_val, 0x83, 0, prv_recon, pseudo_cert_tbs, pca_cert)


pseudo_prv, pseudo_pub = BFExpandAndReconstructKey(
    cert_seed_prv, cert_exp_val, 0x83, 0, prv_recon, pseudo_cert_tbs, pca_cert, pca_pub, pub_recon)

# Sign a BSM with the pseudonym key pair
(R, s, digest, pseudo_cert_dgst) = BSMSigning(bsm_tbs, pseudo_prv, pseudo_cert)
R_out = R.output(compress=True, Ieee1609Dot2=True)
s_out = long2hexstr(s, 32).upper()
print("R: "), print (R_out)
print ("s: " + s_out)

signedbsm += bsm_tbs

# Verify the signed BSM
res = BSMVerify(R, s, bsm_tbs, pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub)
if (res == True):
    print ("BSM successfully verified!")
else:
    print ("ERROR: Failed to verify BSM")

# Get HashedId8 of signing pseudo cert
pseudo_cert_HashedId8 = pseudo_cert_dgst[-16:]
signedbsm += "80" + pseudo_cert_HashedId8
#print ("pseudo_cert_dgst = " + pseudo_cert_dgst.upper())
print ("pseudo_cert_HashedId8 = " + pseudo_cert_HashedId8.upper())

# Insert signature
signedbsm += "80" #ecdsaNistP256Signature
if R_out[0] == "compressed-y-0":
    signedbsm += "82"
elif R_out[0] == "compressed-y-1":
    signedbsm += "83"
else:
    raise Exception("R is not a compressed point")

signedbsm += R_out[1]
signedbsm += s_out

print ("signedbsm = " + signedbsm.upper())
