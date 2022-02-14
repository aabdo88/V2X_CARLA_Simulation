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
# This module encrypts/decrypts data to a public key holder,
# i.e. of type PKRecipientInfo in 1609.2, specifically certRecipInfo:
# - Plaintext is encrypted with AES-CCM using a random AES key
# - The AES key is encrypted to the recipient's public key using
#   ECIES as specified in 1609.2

from __future__ import print_function

from aesccm import * #aes_ccm_enc, aes_ccm_dec
from ecies import * #ecies_enc, ecies_dec

# Generator point on curve NistP256
genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

def PKEncrypt(plaintext, recip_pub_key, recip_cert):
    '''
    Public key encryption as per 1609.2
    The recipient public key is obtained from a certificate, SignedData or by
    other means.
    - The plaintext is encrypted with AES-CCM using a random AES key
    - The AES key is encrypted to the recipient's public key using
      ECIES as specified in 1609.2

    Inputs:
    - plaintext:     {octet string} Data to be encrypted
    - recip_pub_key: {ec256 point}  Recipient's public key
    - recip_cert:    {octet string} Certificate or SignedData where the public
                                    key was retrived or empty string if the
                                    public key was obtained by other means;
                                    needed to compute P1 for ECIES
#
# Test vectors (only runing them when invoked directly, but not when importing it)
#
if __name__ == '__main__':
#
# Test vectors (only runing them when invoked directly, but not when importing it)
#
if __name__ == '__main__':

    Outputs:
    - recip_HashedId8: {octet string} HashedId8 from the digest of recip_cert
                       Note: if recip_cert is the empty string, this field is
                       currently not the correct value; it should be "HashedId8
                       of the COER encoding of a PublicEncryptionKey structure
                       containing the response encryption key." [Guidance Note
                       11] This can be implemented when these corrections are
                       included in a newer version of 1609.2 than
                       1609.2-2016.pdf
    - V:               {ec256 point} Sender's ephemeral public key; output of ECIES
    - C:               {octet string} Encrypted AES key; output of ECIES  (16 octets)
    - T:               {octet string} Authentication tag; output of ECIES (16 octets)
    - nonce:           {octet string} Nonce used with AES-CCM encryption (12 octets)
    - ccm_ciphertext:  {octet string} Ciphertext output of AES-CCM
                                      (= octet length of plaintext + 16 octets)
    '''
    # Generate random AES 128-bit key
    k_long = getrandbits(128)
    k = long2hexstr(k_long, 128)

    nonce_long = getrandbits(12*8)   # 12 bytes
    nonce = long2hexstr(nonce_long, 12*8)

    # Encrypt plaintext with AES-CCM
    ccm_ciphertext = aes_ccm_enc(k, nonce, plaintext)

    # Encrypt AES key with ECIES
    ## P1 = Hash(recipient cert)
    P1 = recip_cert_dgst = sha256(recip_cert.decode('hex')).hexdigest()
    recip_HashedId8 = recip_cert_dgst[-16:]
    V, C, T, _ = ecies_enc(recip_pub_key, k, P1)

    return recip_HashedId8, V, C, T, nonce, ccm_ciphertext

def PKDecrypt(V, C, T, recip_cert, recip_prv_key, nonce, ccm_ciphertext):
    '''
    Public key decryption (with recipient's private key) as per 1609.2
    The recipient uses the private key corresponding to the public key used
    by the sender in the encryption:
    - The AES key is decrypted with ECIES using the recipient's private key
    - The Ciphertext is decrypted with AES-CCM using the AES key
    # Note: the recipient cert should be fetched by and matched with the
    #       the recipient's HashedId8

    Inputs:
    - V:               {ec256 point} Sender's ephemeral public key; input to ECIES
    - C:               {octet string} Encrypted AES key; input to ECIES  (16 octets)
    - T:               {octet string} Authentication tag; input to ECIES (16 octets)
    - recip_cert:      {octet string} Certificate or SignedData where the public
                                      key was retrived or empty string if the
                                      public key was obtained by other means;
                                      needed to compute P1 for ECIES
    - recip_prv_key    {octet string} Recipient's private key (32 octets)
    - nonce:           {octet string} Nonce used with AES-CCM encryption (12 octets)
    - ccm_ciphertext:  {octet string} Ciphertext output of AES-CCM
                                      (= octet length of plaintext + 16 octets)

    Outputs:
    - plaintext        {octet string} decrypted data
    '''
    # Decrypt AES key with ECIES
    ## P1 = Hash(recipient cert)
    P1 = recip_cert_dgst = sha256(recip_cert.decode('hex')).hexdigest()
    k = ecies_dec(V, C, T, recip_prv_key, P1)

    # Decrypt ciphertext with AES-CCM
    plaintext = aes_ccm_dec(k, nonce, ccm_ciphertext)

    return plaintext

#
# Test vectors (only runing them when invoked directly, but not when importing it)
#
if __name__ == '__main__':

    # Generate a key pair to use as the recipient's encryption key
    recip_prv_long = randint(1, genP256.ecc.n-1)
    recip_prv = long2hexstr(recip_prv_long, 256)
    recip_pub = recip_prv_long * genP256

    # Recipient's cert (random value here for testing)
    recip_cert_long = getrandbits(1000)
    recip_cert = long2hexstr(recip_cert_long, 1000)

    # Plaintext (random value here for testing)
    plaintext_long = getrandbits(2000)
    plaintext = long2hexstr(plaintext_long, 2000)

    # Encrypt to recipient's public key
    recip_HashedId8, V, C, T, nonce, ccm_ciphertext = \
        PKEncrypt(plaintext, recip_pub, recip_cert)

    print("recip_prv_key = " + recip_prv)
    recip_pub_out = recip_pub.output(compress=True, Ieee1609Dot2=True)
    print("recip_pub_key = ", recip_pub_out)

    print("plaintext = " + plaintext)
    print("recipientId = " + recip_HashedId8)
    V_out = V.output(compress=True, Ieee1609Dot2=True)
    print("V = ", V_out)
    print("C = " + C)
    print("T = " + T.upper())
    print("nonce = " + nonce)
    print("ccm_ciphertext = " + ccm_ciphertext)

    decrypt_out = PKDecrypt(V, C, T, recip_cert, recip_prv, nonce, ccm_ciphertext)

    if (decrypt_out == plaintext):
        print("Successful Decryption!")
    else:
        print("ERROR: decryption output does not match plaintext")
