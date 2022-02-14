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

import java.io.IOException;

import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.campllc.asn1.generatedmai.ieee1609dot2.*;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.*;
import org.campllc.mbrbuilder.service.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * This is a separate class due to inconsistent ASN versions used in the SCMS modules.
 */
@Service
public class EncryptionServiceMAI {
	@Autowired
	private EncryptionService encryptionService;

	@Autowired
	private CertificateReaderServiceMAI certificateReaderService;

	public Ieee1609Dot2Data encryptIntoDot2Data(String hexMessage, String certFile) throws IOException, InterruptedException, DecoderException {
		// get the recipient key from the certificate
		int yPointUsed = 0;
		Certificate certificate = certificateReaderService.readCertificateFromFile(certFile);
		OctetString yPointValue = null;
		yPointValue = certificate.getToBeSigned().getEncryptionKey().getPublicKey().getEciesNistP256().getCompressed_y_0();
		if (yPointValue != null) {
			yPointUsed = 0;
		} else {
			yPointValue = certificate.getToBeSigned().getEncryptionKey().getPublicKey().getEciesNistP256().getCompressed_y_1();
			if (yPointValue != null) {
				yPointUsed = 1;
			}
		}
		String recipientKey = Hex.encodeHexString(yPointValue.byteArrayValue());

		// encrypt the data using the key
		EncryptionService.EncryptionResult encryptionResult = encryptionService.encrypt(hexMessage, certFile, recipientKey, yPointUsed);

		// fill in the dot2 structure using the results
		EccP256CurvePoint curvePoint;
		if (yPointUsed == 0) {
			curvePoint = EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_0(
					new OctetString(Hex.decodeHex(encryptionResult.ephemeralPubKey.toCharArray())));
		} else {
			curvePoint = EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_1(
					new OctetString(Hex.decodeHex(encryptionResult.ephemeralPubKey.toCharArray())));
		}
		EncryptedDataEncryptionKey encryptionKey = EncryptedDataEncryptionKey.createEncryptedDataEncryptionKeyWithEciesNistP256(
				new EciesP256EncryptedKey(
						curvePoint,
						new OctetString(Hex.decodeHex(encryptionResult.encryptedAESKey.toCharArray())),
						new OctetString(Hex.decodeHex(encryptionResult.authTag.toCharArray()))
				));

		PKRecipientInfo certRecipientInfo = new PKRecipientInfo(
				new HashedId8(Hex.decodeHex(encryptionResult.recipHashedId.toCharArray())), encryptionKey);

		RecipientInfo[] recipient=new RecipientInfo[1];
		//can either be createWithCert or createWithSignedData
		recipient[0] = RecipientInfo.createRecipientInfoWithCertRecipInfo(certRecipientInfo);
		SequenceOfRecipientInfo recipientInfos = new SequenceOfRecipientInfo(recipient);

		AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(new OctetString(
				Hex.decodeHex(encryptionResult.nonce.toCharArray())),
				new Opaque(Hex.decodeHex(encryptionResult.cipherText.toCharArray())));
		EncryptedData encryptedData = new EncryptedData(recipientInfos,
				SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(aesCcmCiphertext));

		Ieee1609Dot2Content content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithEncryptedData(encryptedData);
		Ieee1609Dot2Data encryptedDot2Data = new Ieee1609Dot2Data(new Uint8(3), content);
		return encryptedDot2Data;
	}
}
