#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 24 21:28:16 2020

@author: aabdo
"""

from __future__ import print_function
import os
from hashlib import sha256

from radix import *
from carray import *
from ecc import *
from implicit import *
from bfkeyexp import *


radix_256 = 2**256
radix_8 = 2**8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

def create1609Dot2Digest(tbs, signer_cert):
    # - hash tbs
    tbs_dgst = sha256(tbs.decode('hex')).hexdigest()
    # - hash signer cert
    signer_cert_dgst = sha256(signer_cert.decode('hex')).hexdigest()
    # -- Hash (Hash(tbs)) || Hash (signer_cert))
    digest = sha256((tbs_dgst + signer_cert_dgst).decode('hex')).hexdigest()

    return digest, signer_cert_dgst

def BSMSigning(bsm_tbs, pseudo_prv, pseudo_cert):
    # Create 1609.2 digest of BSM data and pseudo_cert
    bsm_dgst, cert_dgst = create1609Dot2Digest(bsm_tbs, pseudo_cert)

    # Sign digest
    pseudo_prv_long = long(pseudo_prv, 16)
    pseudo_pub  = pseudo_prv_long*genP256
    to_sign = ECDSA(256, pseudo_pub, pseudo_prv)
    # Generate ECDSA signature where r is a point
    (r,s) = to_sign.sign(bsm_dgst, retR_xmodn=False)
    return (r,s, bsm_dgst, cert_dgst)

def reconstructPub(implicit_cert, implicit_cert_tbs, pub_recon, issuer_cert, issuer_pub):
    # Reconstruct public key for implicit cert
    # - create 1609.2 digest of implicit_cert_tbs and issuer_cert
    cert_dgst= create1609Dot2Digest(implicit_cert_tbs, issuer_cert)[0]

    # - reconstruct public key:
    recon_pub = reconstructPublicKey(pub_recon, cert_dgst, issuer_pub, sec4=False, cert_dgst=True)

    return recon_pub

def BSMVerify(r, s, bsm_tbs, pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub):
    pseudo_pub = reconstructPub(pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub)

    # Verify BSM:
    # Create 1609.2 digest of BSM data and pseudo_cert
    bsm_dgst = create1609Dot2Digest(bsm_tbs, pseudo_cert)[0]

    # - verify ECDSA signature on bsm_dgst
    to_verify = ECDSA(256, pseudo_pub)
    if (to_verify.verify(bsm_dgst, r, s)):
        return True
    else:
        return False

def BFExpandAndReconstructKey(seed_prv, exp_val, i, j, prv_recon, pseudo_cert_tbs, pca_cert, pca_pub=None, pseudo_pub_recon=None):
    # Disable printing in some functions
    log_print = False

    # Butterfly expand private key
    bf_prv, bf_pub = bfexpandkey(i, j, exp_val, seed_prv)

    # Reconstruct private key for pseudo cert
    # - create 1609.2 digest of implicit_cert_tbs and issuer_cert
    cert_dgst = create1609Dot2Digest(pseudo_cert_tbs, pca_cert)[0]

    # - reconstruct private key
    pseudo_prv = reconstructPrivateKey(bf_prv, cert_dgst, prv_recon, sec4=False, cert_dgst=True)
    if isinstance(pseudo_prv, basestring):
        pseudo_prv = long(pseudo_prv, 16)

    pseudo_pub = pseudo_prv * genP256

    # If the last parameters are present check that the public key when reconstructed
    # from the cert (as any verifier would do) is the same as pseudo_pub which is
    # obtained from the private key
    if (isinstance(pca_pub, ECPoint) and isinstance(pseudo_pub_recon, ECPoint)):
        recon_pseudo_pub = reconstructPublicKey(pseudo_pub_recon, cert_dgst, pca_pub, sec4=False, cert_dgst=True)
        if (recon_pseudo_pub != pseudo_pub):
            raise Exception("Reconstructed private key and public key do not form a pair")

    # convert pseudo_prv to octet string
    pseudo_prv = long2hexstr(pseudo_prv, bitLen(pseudo_pub.ecc.n))
    return pseudo_prv, pseudo_pub

# Test
if __name__ == '__main__':

    # OBU/25155fde3fd783a3/trustedcerts/pca
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

    # pseudo_cert_tbs extracted from the pseudo_cert
    pseudo_cert_tbs_7A_0 = """
                                  5080 8000
    7a8e 4d44 3b14 03b3 9ffc 0000 000f 8e4d
    443b 1403 b39f fc5e 6f5b 0001 191e 2210
    8400 a983 0103 8000 7c80 01e4 8003 4801
    0200 0120 0001 2681 837a 06e6 dab3 cb6c
    c0b3 7657 1681 7212 3854 690a de9a d8e7
    f1aa 9286 6fc6 c7bd 79
    """.replace("\n","").replace(" ", "")

    # verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
    pub_recon_x_7A_0 = """
                          7a 06e6 dab3 cb6c
    c0b3 7657 1681 7212 3854 690a de9a d8e7
    f1aa 9286 6fc6 c7bd 79
    """.replace("\n","").replace(" ", "")

    # Import the key as an ECPoint
    pub_recon_7A_0 = ECPoint("compressed-y-1", pub_recon_x_7A_0)

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

    # Butterfly-expand and reconstruct a key pair corresponding to cert 7A_0
    pseudo_prv_7A_0, pseudo_pub_7A_0 = BFExpandAndReconstructKey(
        cert_seed_prv, cert_exp_val, 0x7A, 0, prv_recon_7A_0, pseudo_cert_tbs_7A_0, pca_cert)
    print (pseudo_prv_7A_0)
    print (pseudo_pub_7A_0)

    pseudo_prv_7A_0, pseudo_pub_7A_0 = BFExpandAndReconstructKey(
        cert_seed_prv, cert_exp_val, 0x7A, 0, prv_recon_7A_0, pseudo_cert_tbs_7A_0, pca_cert, pca_pub, pub_recon_7A_0)
    print (pseudo_prv_7A_0)
    print (pseudo_pub_7A_0)

    # Sign a BSM with the pseudonym key pair
    bsm_tbs_long = getrandbits(2000)
    bsm_tbs = long2hexstr(bsm_tbs_long, 2000)
    (R, s, digest, cert_dgst) = BSMSigning(bsm_tbs, pseudo_prv_7A_0, pseudo_cert_7A_0)
    print ("R: "), print(R)
    print ("R (1609.2): "), print(R.output(compress=True, Ieee1609Dot2=True))
    print ("s: " + Hex(s, radix_256))

    # Verify the signed BSM
    res = BSMVerify(R, s, bsm_tbs, pseudo_cert_7A_0, pseudo_cert_tbs_7A_0, pub_recon_7A_0, pca_cert, pca_pub)
    if (res == True):
        print ("BSM successfully verified!")
    else:
        print ("ERROR: Failed to verify BSM")