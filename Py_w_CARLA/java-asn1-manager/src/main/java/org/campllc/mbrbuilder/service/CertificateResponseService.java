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
package org.campllc.mbrbuilder.service;

import java.io.*;
import java.util.ArrayList;

import com.oss.asn1.Coder;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.Generated;
import org.campllc.asn1.generated.ieee1609dot2.AesCcmCiphertext;
import org.campllc.asn1.generated.ieee1609dot2.Certificate;
import org.campllc.asn1.generated.ieee1609dot2.EncryptedData;
import org.campllc.asn1.generated.ieee1609dot2basetypes.EciesP256EncryptedKey;
import org.campllc.asn1.generated.ieee1609dot2endentitymainterfacembrbuilder.CertificatePDU;
import org.campllc.asn1.generated.ieee1609dot2pcarainterface.DecryptedCertificateData;
import org.campllc.asn1.generated.ieee1609dot2pcarainterface.ImplicitCertResponse;
import org.campllc.asn1.generated.ieee1609dot2pcarainterface.SignedEncryptedCertificateResponse;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CertificateResponseService {
	private static Log log = LogFactory.getLog(CertificateResponseService.class);

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private PythonRunner pythonRunner;

	public class CertificateResponseParseData {
		public int iVal;
		public int jVal;
		public int yPoint; // ephemeral public key of sender
		public OctetString yValue; // ephemeral public key of sender
		public OctetString c; // encrypted symmetric key
		public OctetString t; // authentication tag
	    public OctetString nonce; // AES nonce
		public OctetString ciphertext; // AES ciphertext
	};

	private CertificateResponseParseData parseSignedEncryptedCertificateResponseFile(String fileName) throws FileNotFoundException, DecodeNotSupportedException, DecodeFailedException {
		CertificateResponseParseData returnData = new CertificateResponseParseData();
		InputStream inputStream = new FileInputStream(fileName);
		Coder coder = Generated.getOERCoder();
		coder.enableAutomaticDecoding();
		SignedEncryptedCertificateResponse asnResponseData = (SignedEncryptedCertificateResponse) coder.decode(inputStream, new SignedEncryptedCertificateResponse());
		EncryptedData encryptedData  = asnResponseData.getContent().getSignedData().getTbsData().getPayload().getData().getContent().getUnsecuredData().getContainedValue().getEncrypted_cert().getContent().getEncryptedData();
		// data set 1
		EciesP256EncryptedKey encryptedKey = encryptedData.getRecipients().get(0).getRekRecipInfo().getEncKey().getEciesNistP256();
		if (encryptedKey.getV().getCompressed_y_0() != null) {
			returnData.yPoint = 0;
			returnData.yValue = encryptedKey.getV().getCompressed_y_0();
		} else if (encryptedKey.getV().getCompressed_y_1() != null) {
			returnData.yPoint = 1;
			returnData.yValue = encryptedKey.getV().getCompressed_y_1();
		}
		returnData.c = encryptedKey.getC();
		returnData.t = encryptedKey.getT();
		// data set 2
		AesCcmCiphertext aesCcmCiphertext = encryptedData.getCiphertext().getAes128ccm();
		returnData.nonce = aesCcmCiphertext.getNonce();
		returnData.ciphertext = aesCcmCiphertext.getCcmCiphertext();
		// i and j values
		File f = new File(fileName);
		String[] fileNameParts = f.getName().split("_");
		returnData.iVal = (int)Long.parseLong(fileNameParts[0], 16);
		returnData.jVal = (int)Long.parseLong(fileNameParts[1], 16);
		return returnData;
	}

	public void processCertificateFile(String fileName, String encExpansion, String encPrivateKey) throws Exception {
		log.info("Processing certificate file: " + fileName);
		// parse the SignedEncryptedCertificateResponse
		CertificateResponseService.CertificateResponseParseData parseData = parseSignedEncryptedCertificateResponseFile(fileName);
		log.info("i=0x" + Integer.toHexString(parseData.iVal));
		log.info("j=0x" + Integer.toHexString(parseData.jVal));
		log.info("y=" + parseData.yPoint);
		log.info("yValue=" + Hex.encodeHexString(parseData.yValue.byteArrayValue()));
		log.info("c=" + Hex.encodeHexString(parseData.c.byteArrayValue()));
		log.info("t=" + Hex.encodeHexString(parseData.t.byteArrayValue()));
		log.info("nonce=" + Hex.encodeHexString(parseData.nonce.byteArrayValue()));
		log.info("ciphertext=" + Hex.encodeHexString(parseData.ciphertext.byteArrayValue()));
		// decrypt to a Ieee1609Dot2Data/UnsecuredData which is a PlaintextCertificateResponse
		ArrayList<String> arguments = new ArrayList<>();
		arguments.add("-i");
		arguments.add(Integer.toString(parseData.iVal));
		arguments.add("-j");
		arguments.add(Integer.toString(parseData.jVal));
		arguments.add("-y");
		arguments.add(Integer.toString(parseData.yPoint));
		arguments.add("--yValue");
		arguments.add(Hex.encodeHexString(parseData.yValue.byteArrayValue()));
		arguments.add("-c");
		arguments.add(Hex.encodeHexString(parseData.c.byteArrayValue()));
		arguments.add("-t");
		arguments.add(Hex.encodeHexString(parseData.t.byteArrayValue()));
		arguments.add("--nonce");
		arguments.add(Hex.encodeHexString(parseData.nonce.byteArrayValue()));
		arguments.add("--ciphertext");
		arguments.add(Hex.encodeHexString(parseData.ciphertext.byteArrayValue()));
		arguments.add("--encExpansion");
		arguments.add(encExpansion);
		arguments.add("--encSeed");
		arguments.add(encPrivateKey);
		String[] decryptOutput = pythonRunner.runPythonScript("decrypt_cert_response.py",arguments);
		log.info("decrypt output = " + decryptOutput[0]);

		// save the DecryptedCertificateData
		byte[] decryptedCertificateDataBytes = Hex.decodeHex(decryptOutput[0].toCharArray());
		String decryptedCertFileName = fileName + ".dcert";
		log.info("Writing decrypted certificate file: " + decryptedCertFileName);
		FileOutputStream decryptedCertOutputStream = new FileOutputStream(decryptedCertFileName);
		decryptedCertOutputStream.write(decryptedCertificateDataBytes);

		// parse out the DecryptedCertificateData
		DecryptedCertificateData decryptedCertificateData = asnEncoder.decodeDecryptedCertificateData(
				decryptedCertificateDataBytes);
		ImplicitCertResponse implicitCertResponse = decryptedCertificateData.getContent().getUnsecuredData().getContainedValue().getImplicit_butterfly();

		// get the certificate bytes and write them
		Certificate certificate = implicitCertResponse.getCertificate();
		CertificatePDU certificatePDU = new CertificatePDU(
				certificate.getVersion(),
				certificate.getType(),
				certificate.getIssuer(),
				certificate.getToBeSigned(),
				certificate.getSignature());
		CommMsg certificateData = asnEncoder.simpleEncode(certificatePDU);
		byte[] reconstructionKey = implicitCertResponse.getPriv_key_reconstruction_s().byteArrayValue();

		log.info("certData=" + certificateData.toHex());
		log.info("reconstructData=" + Hex.encodeHexString(reconstructionKey));

		/// save the files off
		String certFileName = fileName + ".cert";
		log.info("Writing certificate file: " + certFileName);
		FileOutputStream certOutputStream = new FileOutputStream(certFileName);
		certOutputStream.write(certificateData.getMsg());
		String reconstructFileName = fileName + ".s";
		certOutputStream.close();
		log.info("Writing key reconstruction file: " + reconstructFileName);
		FileOutputStream reconstructOutputStream = new FileOutputStream(reconstructFileName);
		reconstructOutputStream.write(reconstructionKey);
		reconstructOutputStream.close();
	}

}
