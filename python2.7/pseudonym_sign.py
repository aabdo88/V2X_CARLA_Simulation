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
Created on Jun 26, 2017

@author: Griff Baily
'''
from __future__ import print_function
import os
import binascii
from hashlib import sha256
from optparse import OptionParser
parser=OptionParser()
parser.add_option("-f", "--file", dest="filedir", help="base directory for cert", metavar="DIR")
parser.add_option("-i", "--certi", dest="certname", help="cert name (i value)", metavar="CERTI")
parser.add_option("-j", "--certj", dest="certnumber", help="cert number (j value)", metavar="CERTJ")
parser.add_option("", "--pcaFile", dest="pcaFile", help="PCA file path)", metavar="PCAFILE")
parser.add_option("", "--pcaYPoint", dest="pcaYPoint", help="PCA y point (0 or 1)", metavar="PCAY")
parser.add_option("-p", "--pcaPublic", dest="pcaPub", help="PCA public key in hex", metavar="PCAPUB")
parser.add_option("-b", "--bsm", dest="bsm_tbs",help="contents of bsm in hex", metavar="BSM")
(options,args)=parser.parse_args()
from array import *
from ecc import *
from implicit import *
from bfkeyexp import *
from radix import *
from pseudosign import *
radix_256 = 2**256
radix_8 = 2**8

directory=options.filedir
certname=options.certname
certfull=options.certname.upper()+"_"+options.certnumber

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)
# Test
pca_in=open(options.pcaFile,"rb")
# OBU/25155fde3fd783a3/trustedcerts/pca
pca_cert = binascii.hexlify(pca_in.read())
pca_in.close()

pca_pub = ECPoint("compressed-y-"+options.pcaYPoint, options.pcaPub)

# OBU/25155fde3fd783a3/download/7a/
pseudo_in=open(directory+"/download/"+certname+"/"+certfull+".cert","rb")
# 7A_0.cert
pseudo_cert= binascii.hexlify(pseudo_in.read())
pseudo_in.close()

# pseudo_cert_tbs extracted from the pseudo_cert
pseudo_cert_tbs=pseudo_cert[24:]

# verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
#
pub_recon_x= pseudo_cert_tbs[-64:]
# Import the key as an ECPoint
# Check if the reconstruction point is compressed-y-0 or compressed-y-1
if (pseudo_cert_tbs[-66:-64] == "82"):
    pub_recon = ECPoint("compressed-y-0", pub_recon_x)
else: #"83"
    pub_recon= ECPoint("compressed-y-1", pub_recon_x)

prv_recon_in = open(directory+"/download/"+certname+"/"+certfull+".s","rb")
prv_recon = binascii.hexlify(prv_recon_in.read())
prv_recon_in.close()

#OBU/25155fde3fd783a3/dwnl_sgn.priv
cert_seed_in=open(directory+"/../verify_key.priv","rb")
cert_seed_prv = binascii.hexlify(cert_seed_in.read())
cert_seed_in.close()

# OBU/25155fde3fd783a3/sgn_expnsn.key
cert_exp_in=open(directory+"/../verify_expansion.priv","rb")
cert_exp_val =binascii.hexlify(cert_exp_in.read())
cert_exp_in.close()


#Butterfly-expand and reconstruct a key pair corresponding to cert
pseudo_prv, pseudo_pub = BFExpandAndReconstructKey(
    cert_seed_prv, cert_exp_val, long(options.certname,16), long(options.certnumber,16), prv_recon, pseudo_cert_tbs, pca_cert, pca_pub, pub_recon)

# Sign a BSM with the pseudonym key pair
bsm_tbs = options.bsm_tbs
(R, s, digest,cert_dgst) = PseudonymSign(bsm_tbs, pseudo_prv, pseudo_cert)
print(R.output(compress=True, Ieee1609Dot2=True))
print (Hex(s, radix_256))
print(cert_dgst[-16:])
