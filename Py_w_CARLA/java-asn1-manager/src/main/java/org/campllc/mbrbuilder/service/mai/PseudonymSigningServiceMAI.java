/*
 * (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.campllc.mbrbuilder.service.mai;

import java.math.BigInteger;

import com.oss.asn1.AbstractData;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.binary.Hex;
import org.campllc.asn1.generatedmai.ieee1609dot2.*;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.*;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.service.PropertyService;
import org.campllc.mbrbuilder.service.PseudonymSigningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PseudonymSigningServiceMAI {

	@Autowired
	private CertificateReaderServiceMAI certificateReaderService;

	@Autowired
	private PseudonymSigningService signingService;

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private ASNEncoderMAI asnEncoder;

	public Ieee1609Dot2Data signIntoDot2Data(Opaque dataToSign, int psid, int timeGenerationOffset, String certDir, String certGroup, String certNumber) throws Exception {
		Ieee1609Dot2Content dot2Content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithUnsecuredData(dataToSign);
		Ieee1609Dot2Data dot2Data = new Ieee1609Dot2Data(new Uint8(3), dot2Content);
		SignedDataPayload payload = new SignedDataPayload(dot2Data,new HashedData());
		payload.deleteExtDataHash();

		// prep header information
		HeaderInfo headerInfo = new HeaderInfo();
		headerInfo.setPsid(new Psid(psid));
		Certificate signingCert = certificateReaderService.readPseudonymCertificate(certDir, certGroup, certNumber);
		//start time (in seconds since the 1609.2 epoch) of validity period
		int startTime=signingCert.getToBeSigned().getValidityPeriod().getStart().intValue();
		//duration of validity in hours
		int duration=signingCert.getToBeSigned().getValidityPeriod().getDuration().getHours().intValue();
		//end time (in seconds since the 1609.2 epoch) of validity period
		long endTime=(long)startTime+((long)(duration*60*60));
		long time=((long)startTime+timeGenerationOffset)*((long)Math.pow(10,6));
		// TODO fill in desired time
		//long time= ((long)Math.pow(10,3))*(Instant.now().toEpochMilli()-(((long)1072915200)*((long)1000)));
		headerInfo.setGenerationTime(new Time64(BigInteger.valueOf(time)));
		//headerInfo.setExpiryTime(getExpiryTime());
		// TODO
		headerInfo.setGenerationLocation( new ThreeDLocation(
						new Latitude(0),
						new Longitude(0),
						new Elevation(0)
				)
		);
		//headerInfo.setP2pcdLearningRequest(getP2pcdReq());
		//headerInfo.setMissingCrlIdentifier(getMissingCRLIdent());
		//headerInfo.setInlineP2pcdRequest(new SequenceOfHashedId3(getInlineP2pcd()));

		// set up the data to be signed
		ToBeSignedData tbs = new ToBeSignedData(payload,headerInfo);
		// encode the payload
		CommMsg msg = asnEncoder.encodeTBSData(tbs);

		// create the signature based on the cert and data to sign
		PseudonymSigningService.PseudonymSigningResult signingResult = signingService.signPayload(
				msg.getMsg(), certDir, certGroup, certNumber,
				propertyService.getComponentCertificateFile("pca").getAbsolutePath());
		Certificate[] certSequence = new Certificate[1];
		certSequence[0] = signingCert;
		OctetString sOct = new OctetString(Hex.decodeHex(signingResult.sSig.toCharArray()));
		OctetString rOct = new OctetString(Hex.decodeHex(signingResult.rSig.toCharArray()));
		EcdsaP256Signature signature;
		if (signingResult.yPoint == 0) {
			signature = new EcdsaP256Signature(EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_0(rOct),sOct);
		} else {
			signature = new EcdsaP256Signature(EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_1(rOct),sOct);
		}

		// create the dot2 wrapper
		SignedData signedData = new SignedData(
				HashAlgorithm.sha256, tbs,
				SignerIdentifier.createSignerIdentifierWithCertificate(new SequenceOfCertificate(certSequence)),
				Signature.createSignatureWithEcdsaNistP256Signature(signature)
		);
		Ieee1609Dot2Content dot2ContentSigned = Ieee1609Dot2Content.createIeee1609Dot2ContentWithSignedData(signedData);
		Ieee1609Dot2Data dot2DataReturn = new Ieee1609Dot2Data(new Uint8(3), dot2ContentSigned);
		return dot2DataReturn;
	}

	public Ieee1609Dot2Data signAbstractDataIntoDot2Data(AbstractData dataToSign, int psid, int timeGenerationOffset, String certDir, String certGroup, String certNumber) throws Exception {
		// get the content to sign
		CommMsg data = asnEncoder.simpleEncode(dataToSign);
		return signIntoDot2Data(new Opaque(data.getMsg()), psid, timeGenerationOffset, certDir, certGroup, certNumber);
	}
}
