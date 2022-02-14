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

    pca_cert = """
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
    pca_pub = ECPoint("compressed-y-0", pca_pub_x)
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
    message = sys.argv[1]
    BSM_sighned = message[:-4]
    lenghts = message[-4:]
    R_len = int(lenghts[:-2])
    s_len = int(lenghts[-2:])
    s = BSM_sighned[-s_len:]
    new_BSM_sighned = BSM_sighned[:-s_len]
    R = new_BSM_sighned[-R_len:]
    received_hex = BSM_sighned[6:]
    skip = 22 + R_len + s_len
    received_hex = received_hex[:-skip]
    bsm_tbs = received_hex
    # pseudo_cert_tbs extracted from the pseudo_cert
    pseudo_cert_tbs = pseudo_cert_7A_0[24:]
    # verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
    pub_recon_x = pseudo_cert_tbs[-64:]
    # Import the key as an ECPoint
    # Check if the reconstruction point is compressed-y-0 or compressed-y-1
    if (pseudo_cert_tbs[-66:-64] == "82"):
        pub_recon = ECPoint("compressed-y-0", pub_recon_x)
    else: #"83"
        pub_recon = ECPoint("compressed-y-1", pub_recon_x)
    # Verify the signed BSM
    res = BSMVerify(R, s, bsm_tbs, pseudo_cert_7A_0, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub)
    output = str(res) + ":" + bsm_tbs[8:]
    print(output)
