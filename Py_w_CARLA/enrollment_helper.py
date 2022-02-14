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
from ecc import *
from implicit import *
from pkencrypt import *
from pseudosign import *

# CAMP PoC Enrollment Request Helper Script
#
# Further instructions available via CAMP Wiki
#       https://wiki.campllc.org/pages/viewpage.action?pageId=58589462
#
# Using ASN.1 Tools, create a ScopedEeEnrollmentCertRequest. You are responsible
# for choosing appropriate values for the following fields. The rest can be
# default values. Sample data for a BSM-transmitting vehicle follows:
#
#   tbsData.crlSeries = EeEnrollmentCrlSeries = 4
#   tbsData.validityPeriod.start = <current time, Ieee1609Dot2 format>
#   tbsData.validityPeriod.duration = ObeEnrollmentCertExpirationPoc = {years(30)}
#   tbsData.region.identifiedRegion = USA = {countryOnly(840)}
#          # Canada (124) and/or Mexico(484) can possibly be included too
#   tbsData.certRequestPermissions =
#               subjectPermissions explicit :
#                   { {psid 32, sspRange opaque : {} },     # BSMs
#                     {psid 38, sspRange opaque : {} } }    # Misbehavior reporting
#               minChainDepth = 0
#               chainDepthRange = 0
#               eeType = enroll = 1
#
# The high level description:
#   Generate a keypair and place the public key in the request
#   Place in a SignedEeEnrollmentCertRequest and self-sign
#   Package in a zip file with correct filename
#   Process the response


def enrollKeyGen() :
    # compute an ECC keypair for the request
    prv_long = randint(1, genP256.ecc.n-1)
    reqPrv = "{0:0>{width}X}".format(prv_long, width=bitLen(genP256.ecc.n)*2/8)
    reqPub = prv_long*genP256
    return (reqPrv, reqPub)


def selfSignEnrollRequest(tbsRequest, reqPrv, reqPub) :
    digest = create1609Dot2Digest(tbsRequest, "")[0]
    to_sign = ECDSA(256, reqPub, reqPrv)
    # Generate ECDSA signature where r is a point
    (r,s) = to_sign.sign(digest, retR_xmodn=False)
    return (r,s)


def reconstructEnrollKey(tbsCert, ecaCert, reqPrv, prvRecon) :
    digest = create1609Dot2Digest(tbsCert, ecaCert)[0]
    prv = reconstructPrivateKey(reqPrv, digest, prvRecon)
    pub = long(prv, 16) * genP256
    return (prv,pub)


if __name__ == "__main__":

####
# Step 1: Create the eeEcaCertRequest
#
# Need to generate an ECC keypair and place the public key in the request
####

    # Set current time in tbsData

    # Generate the public key for the request
    # Need to remember the private key to handle response
    reqPrv, reqPub = enrollKeyGen()

    print("\nBase request keypair:")
    print("reqPrv: " + reqPrv)
    print("reqPub: PublicVerificationKey : ecdsaNistP256 : " + str(reqPub.output(compress=True, Ieee1609Dot2=True)))

    # Set VerifyKeyIndicator in tbsData, as computed above


####
# Step 2: Create the SignedEeEnrollmentCertRequest
#
# Generate (r,s) for the signature, and set Signer=SELF
####

# Let request = SignedEeEnrollmentCertRequest
# Let request.tbsRequest = ScopedEeEnrollmentCertRequest
# Let tbsData = request.tbsRequest.eca-ee.eeEcaCertRequest.tbsData

    # Replace this with the COER encoded tbsRequest (ScopedEeEnrollmentCertRequest)
    tbsRequest = "00112233445566778899AABBCCDDEEFF"

    (r,s) = selfSignEnrollRequest(tbsRequest, reqPrv, reqPub)

    print("\nSignature for SignedEeEnrollmentCertRequest:")

    # Set request.signer = SELF
    print("Signer : SELF")

    # Set request.signature:
    # r -> request.signature.ecdsaNistP256Signature.r
    print("r: (\"x-only\", " + r.output(compress=True, Ieee1609Dot2=True)[1].upper() + ")")

    # s -> request.signature.ecdsaNistP256Signature.s
    print("s: " + '{:X}'.format(s))


####
# Step 3: Place encoded SignedEeEnrollmentCertRequest into zipfile
#
# The name of the file is <hash_of_OER_public_key>.oer
# The contents of the file is the encoded Signed request
# Multiple requests can be included in one archive
# NOTE: Assuming that OER encoding is of the PublicVerificationKey object
####

    # I think this should be the OER encoded PublicVerificationKey object. Simple
    # manual encoder here should work, or replace it with output from ASN.1 tools.
    typeStr,xStr = reqPub.output(compress=True, Ieee1609Dot2=True)
    encodedPub = "0080" + ("82" if typeStr == "compressed-y-0" else "83") + xStr.upper()

    filename = sha256(encodedPub.decode('hex')).hexdigest().upper()
    print("\nFilename: " + filename + ".oer")
    print("    (hash of OER encoded reqPub, as above)")

    # The encoded signed request is added to the archive with the above filename


####
# Step 4: Handle the response
####

    # NOTE: These values do not correspond to the previous steps, just sample data,
    # need to replace them with the actual value from the response.

    # ECA certificate
    #<hash>/eca.oer
    eca = "8003008057C95A3362F1FC395981146563612E746573742E76327873636D732E636F6DF1FC390002197A6B1086000383010380007C8001E480034801018001238003840001010120814000808344E2829E31780E4054EF1B778C39F66DC19AC6AFB1E84B982B4DB11EEAEB0498808082A77035BED3FAA90AED52770AE9DDC402480CAF081AA459DE81F3AF2E95FD6A88808065B61711818B6D7D5244BCFA88DED04A263C3EF3425727392AF97C41407FCF4C11B5D7F1C4F3C79100B369684719955D6E37F9A825F7B283369613789BA0E65A"

    # The toBeSignedCertificate portion of the enrollment cert
    # <hash>/enrollment.oer
    enrollTbs = "448100D462C000041A11089B8410E083010180034801018080010280012080010080012680010001008183CE5B069794E289E481EC0649380C5D1588FF97F572659FD83D157E8B447C706A"

    # <hash>/enrollment.s
    prvRecon = "11E2134FF857E3CFDCE04E545D85077173D4F68350CC784CA410255C05387D57"

    enrollPrv, enrollPub = reconstructEnrollKey(enrollTbs, eca, reqPrv, prvRecon)

    print("\nReconstructed enrollment private key: " + enrollPrv)

    # Should now be able to sign data with (enroll, enrollPrv)
