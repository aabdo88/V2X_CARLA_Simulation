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
from bsmsign import *
import os
import sys
       
# ==============================================================================
# -- main() --------------------------------------------------------------------
# ==============================================================================


if __name__ == '__main__':

    pca_cert = pca_cert = """
        8003 0080 fabd 443d bf85 85fa 5981 1676
        3278 7063 612d 7465 7374 2e67 6873 6973
        732e 636f 6d5e 6f5b 0002 18f3 4861 8600
        0a83 0103 8000 7c80 01e4 8003 4801 0180
        0123 8003 8500 0101 0100 8001 0200 0120
        0001 2600 8082 42ac 6bc3 42c4 93d2 a6a8
        2169 fc25 2ebf 6c86 ba6a 3285 b143 2376
        1a43 de15 ff80 8080 827c 5c5a d2e4 4129
        9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
        dd9e 8e39 188f a57f ef80 8000 e93d b970
        f630 d6f5 c4f0 a9e2 7a57 85f1 43e3 e82f
        9090 a76a 882f 08c6 3f79 51ec b93a c48b
        4f5b 6aac b052 35c8 230b 5c2a b624 f0df
        36cb f0f0 2f33 01b9 cf5f 69
        """.replace("\n","").replace(" ", "")
    pca_pub_x = """
                              7c 5c5a d2e4 4129
        9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
        dd9e 8e39 188f a57f ef
        """.replace("\n","").replace(" ", "")
    # OBU/25155fde3fd783a3/download/7a/
    # 7A_0.cert
    pseudo_cert_7A_0 = """
        0003 0180 da76 6b0e 278f d23d 5080 8000
        7a8e 4d44 3b14 03b3 9ffc 0000 000f 8e4d
        443b 1403 b39f fc5e 6f5b 0001 191e 2210
        8400 a983 0103 8000 7c80 01e4 8003 4801
        0200 0120 0001 2681 837a 06e6 dab3 cb6c
        c0b3 7657 1681 7212 3854 690a de9a d8e7
        f1aa 9286 6fc6 c7bd 79
        """.replace("\n","").replace(" ", "")

    # OBU/25155fde3fd783a3/download/7a/
    # 7A_0.s
    prv_recon_7A_0 = """
        08fa 4ce5 2c68 b12b b8ba f94a 15d5 7aed
        c82b f842 7997 75ec 520a c28b 31e7 d907
        """.replace("\n","").replace(" ", "")
    # OBU/25155fde3fd783a3/dwnl_sgn.priv
    cert_seed_prv = """
        4655 5a86 2db4 4758 e8a9 cbcb b0ab aec6
        bf91 d38d ac24 11f5 3f59 1867 4a1c b1ad
        """.replace("\n","").replace(" ", "")
    # OBU/25155fde3fd783a3/sgn_expnsn.key
    cert_exp_val = """
        9d53 e9d9 626e 647c edd7 bd6a a7fd e192
        """.replace("\n","").replace(" ", "")
            
            
    # 1609.2 epoch in seconds
    epoch1609Dot2 = 1072915200
    ## BSM1_1
    bsm1_1 = str(sys.argv[0])
    
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
    bsm_tbs += long2hexstr(generationTime, 64).lower()
      
    pca_pub = ECPoint("compressed-y-0", pca_pub_x)
    # pseudo_cert_tbs extracted from the pseudo_cert
    pseudo_cert_tbs_7A_0 = pseudo_cert_7A_0[24:]
    # verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
    pub_recon_x_7A_0 = pseudo_cert_tbs_7A_0[-64:]
    # Import the key as an ECPoint
    pub_recon_7A_0 = ECPoint("compressed-y-1", pub_recon_x_7A_0)
       
    # Butterfly-expand and reconstruct a key pair corresponding to cert 7A_0
    pseudo_prv_7A_0, pseudo_pub_7A_0 = BFExpandAndReconstructKey(
    cert_seed_prv, cert_exp_val, 0x7A, 0, prv_recon_7A_0, pseudo_cert_tbs_7A_0, pca_cert, pca_pub, pub_recon_7A_0)
    
    # Sign a BSM with the pseudonym key pair
    (R, s, digest, cert_dgst) = BSMSigning(bsm_tbs, pseudo_prv_7A_0, pseudo_cert_7A_0)
    
    R_out = R.output(compress=True, Ieee1609Dot2=True)
    s_out = long2hexstr(s, 32).upper()
    
    signedbsm += bsm_tbs
    
    # Get HashedId8 of signing pseudo cert
    pseudo_cert_HashedId8 = cert_dgst[-16:]
    signedbsm += "80" + pseudo_cert_HashedId8
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
    signedbsm += str(len(R_out[1]))
    signedbsm += str(len(s_out))
    output = signedbsm + ":" + pseudo_cert_7A_0 + ":" + pca_cert + ":" + pca_pub
    print(output)
