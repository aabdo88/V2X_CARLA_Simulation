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
    
    message = str(sys.argv[0])
    pseudo_cert = str(sys.argv[1])
    pca_cert = str(sys.argv[2]) 
    pca_pub = str(sys.argv[3])
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
    pseudo_cert_tbs = pseudo_cert[24:]
    # verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
    pub_recon_x = pseudo_cert_tbs[-64:]
    # Import the key as an ECPoint
    # Check if the reconstruction point is compressed-y-0 or compressed-y-1
    if (pseudo_cert_tbs[-66:-64] == "82"):
        pub_recon = ECPoint("compressed-y-0", pub_recon_x)
    else: #"83"
        pub_recon = ECPoint("compressed-y-1", pub_recon_x)
    # Verify the signed BSM
    res = BSMVerify(R, s, bsm_tbs, pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub)

    output = res + ":" + bsm_tbs[8:]
    print(output)
        
    
