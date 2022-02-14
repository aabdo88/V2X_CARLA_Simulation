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
#####
# This script generates test vectors for group linkage values glv(i,j)
# for i = {0,1} and j randomly chosen 32-bit value.
#####

from lv import *

def genei(ik, j, k):
    aes_obj = AES.new(ik.decode('hex'), AES.MODE_ECB)

    print("Encrypted indices function AES input = j (32-bit) || k (32-bit) || 0 (64-bit) =")
    aes_in_j_k = "{0:032X}".format(((j << 32) + k) << 64)
    print("0x" + aes_in_j_k)
    cArrayDef("", "aes_in_j_k", long(aes_in_j_k, 16), 128/8, radix_8, False); print(os.linesep)

    print("AES output (128 bits) = AES_ik (j || k || 0^{64}) =")
    aes_out_j_k = aes_obj.encrypt(aes_in_j_k.decode('hex')).encode('hex')
    print("0x" + aes_out_j_k.upper())
    cArrayDef("", "aes_out_j_k", long(aes_out_j_k, 16), 128/8, radix_8, False); print(os.linesep)

    print("ei(j,k): Encrypted indices function = AES output XOR AES input (128 bits) = ")
    ei_j_k = long(aes_in_j_k, 16) ^ long(aes_out_j_k, 16)
    print(Hex(ei_j_k, radix_128))
    cArrayDef("", "ei_j_k", ei_j_k, 128/8, radix_8, False); print(os.linesep)

    return ei_j_k

if __name__ == '__main__':


    print("""
Test vectors for Group Linkage Values glv(i,j)
for i = {0,1} and j randomly chosen 32-bit value for test purposes
==================================================================

Note: the argument k is not included in the notation of gplv1(i,j,k), gs1(i,k),
      gplv2(i,j,k), gs2(i,k) and glv(i,j,k) below
      as it is not included in their computation
""")

    print("LA1 ID (16 bits) =")
    la_id1 = getrandbits(16)
    print(Hex(la_id1, radix_16) + os.linesep)

    print("LA2 ID (16 bits) =")
    la_id2 = getrandbits(16)
    print(Hex(la_id2, radix_16) + os.linesep)

    print("k: group chain identifier (32 bits) =")
    k = getrandbits(32)
    print(Hex(k, radix_32) + os.linesep)

    print("ik: indices key shared between LA1 and LA2 (128 bits) =")
    ik = "{0:032X}".format(getrandbits(128))
    print("0x" + ik)

    print("""
i = 0
=====
j is a randomly chosen 32-bit value
""")

    print("j (32 bits) =")
    j = getrandbits(32)
    print(Hex(j, radix_32) + os.linesep)

    print("LA1")
    print("---")
    gls1_0 = genls(1, 0, None, None, prefix = "gs")
    gplv1_0_j = genplv(1, 0, la_id1, gls1_0, j, prefix = "gplv", keyname = "gs")

    print("LA2")
    print("---")
    gls2_0 = genls(2, 0, None, None, prefix = "gs")
    gplv2_0_j = genplv(2, 0, la_id2, gls2_0, j, prefix = "gplv", keyname = "gs")

    print("glv(0,j)")
    print("----------")
    lv_0_j = genlv(0, gplv1_0_j, gplv2_0_j, "g")

    print("ei(j,k)")
    print("-------")
    ei_j_k = genei(ik, k, j)

    print("""
i = 1
=====
j is a randomly chosen 32-bit value
""")

    print("j (32 bits) =")
    j = getrandbits(32)
    print(Hex(j, radix_32) + os.linesep)

    print("LA1")
    print("---")
    gls1_1 = genls(1, 1, la_id1, gls1_0, prefix = "gs")
    gplv1_1_j = genplv(1, 1, la_id1, gls1_1, j, prefix = "gplv", keyname = "gs")

    print("LA2")
    print("---")
    gls2_1 = genls(2, 1, la_id2, gls2_0, prefix = "gs")
    gplv2_1_j = genplv(2, 1, la_id2, gls2_1, j, prefix = "gplv", keyname = "gs")

    print("glv(1,j)")
    print("-------")
    lv_1_j = genlv(1, gplv1_1_j, gplv2_1_j, "g")

    print("ei(j,k)")
    print("-------")
    ei_j_k = genei(ik, k, j)
