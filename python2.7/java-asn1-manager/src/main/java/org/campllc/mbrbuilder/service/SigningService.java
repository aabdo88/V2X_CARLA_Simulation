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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

import com.oss.asn1.AbstractData;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.binary.Hex;
import org.campllc.asn1.generated.ieee1609dot2.*;
import org.campllc.asn1.generated.ieee1609dot2basetypes.*;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedCertificateRequest;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.SignedCertificateRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SigningService {

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private CertificateReaderService certificateReaderService;

	@Autowired
	private PythonRunner pythonRunner;

	public class SigningResult {
		public CurvePoint rSig;
		public String sSig;
		public String digest;
	}

	public SigningResult signDataExplicit(CommMsg bytesToSign, Certificate certificate, String privateKeyFile) throws Exception {
		ArrayList<String> arguments = new ArrayList<>();
        boolean passAsFile = true;
        if (passAsFile) {
            File bytesRequestFile = new File(propertyService.getSharedFilesDirectory(), "sign_explicit.oer");
            FileOutputStream fileOutputStream = new FileOutputStream(bytesRequestFile.getPath());
            PrintWriter printWriter = new PrintWriter(fileOutputStream);
            printWriter.print(bytesToSign.toHex());
            printWriter.close();
            arguments.add("-f");
            arguments.add(bytesRequestFile.getAbsolutePath());
        } else {
            arguments.add("-d");
            arguments.add(bytesToSign.toHex());
        }
		arguments.add("-p");
		byte[] privateKeyData = Files.readAllBytes(Paths.get(privateKeyFile));
		arguments.add(Hex.encodeHexString(privateKeyData));
		arguments.add("-c");
		arguments.add(asnEncoder.simpleEncode(certificate).toHex());
		String [] output = pythonRunner.runPythonScript("sign_explicit_file.py", arguments);
		SigningResult returnData = new SigningResult();
		returnData.rSig = new CurvePoint();
		returnData.rSig.readFromPythonOutput(output[0]);
		returnData.sSig = output[1].substring(2);
		returnData.digest = output[2];
		return returnData;
	}

	public SignedCertificateRequest signCertificateRequest(ScopedCertificateRequest scopedCertificateRequest, Certificate certificate, String privateKeyFile) throws Exception {
		CommMsg bytesToSign = asnEncoder.simpleEncode(scopedCertificateRequest);
		SigningResult signingResult = signDataExplicit(bytesToSign, certificate, privateKeyFile);

		EcdsaP256Signature ecdsaP256Signature = new EcdsaP256Signature(
				signingResult.rSig.createEccP256CurvePoint(),
				new OctetString(Hex.decodeHex(signingResult.sSig.toCharArray()))
		);

		SequenceOfCertificate sequenceOfCertificate = new SequenceOfCertificate();
		sequenceOfCertificate.add(certificate);
		SignedCertificateRequest signedCertificateRequest = new SignedCertificateRequest(
				HashAlgorithm.sha256, scopedCertificateRequest,
				SignerIdentifier.createSignerIdentifierWithCertificate(sequenceOfCertificate),
				Signature.createSignatureWithEcdsaNistP256Signature(ecdsaP256Signature)
		);

		return signedCertificateRequest;
	}

	public Ieee1609Dot2Data signIntoDot2Data(CommMsg data, Certificate certificate, String privateKeyFile, int psid) throws Exception {
		Ieee1609Dot2Content dot2Content =
				Ieee1609Dot2Content.createIeee1609Dot2ContentWithUnsecuredData(new Opaque(data.getMsg()));
		Ieee1609Dot2Data dot2Data = new Ieee1609Dot2Data(new Uint8(3), dot2Content);
		SignedDataPayload payload = new SignedDataPayload(dot2Data,new HashedData());
		payload.deleteExtDataHash();

		// prep header information
		HeaderInfo headerInfo = new HeaderInfo();
		headerInfo.setPsid(new Psid(psid));

		// set up the data to be signed
		ToBeSignedData tbs = new ToBeSignedData(payload,headerInfo);
		// encode the payload
		CommMsg msg = asnEncoder.encodeTBSData(tbs);

		// create the signature based on the cert and data to sign
		SigningResult signingResult = signDataExplicit(msg, certificate, privateKeyFile);
		Certificate[] certSequence = new Certificate[1];
		certSequence[0] = certificate;
		OctetString s = new OctetString(Hex.decodeHex(signingResult.sSig.toCharArray()));
		EccP256CurvePoint curvePoint = signingResult.rSig.createEccP256CurvePoint();
		EcdsaP256Signature signature = new EcdsaP256Signature(curvePoint, s);

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

	public Ieee1609Dot2Data signIntoDot2Data(AbstractData dataToSign, Certificate certificate, String privateKeyFile, int psid) throws Exception {
		CommMsg data = asnEncoder.simpleEncode(dataToSign);
		return signIntoDot2Data(data, certificate, privateKeyFile, psid);
	}

	public Ieee1609Dot2Data signComponentMessage(AbstractData dataToSign, String sendingComponent) throws Exception {
		Certificate certificate = certificateReaderService.readCertificateFromFile(
				propertyService.getComponentCertificateFile(sendingComponent).getAbsolutePath()
		);
		File privateKeyFile = propertyService.getComponentSigningPrivateKeyFile(sendingComponent);
		// 35 is security management PSID
		return signIntoDot2Data(dataToSign, certificate, privateKeyFile.getAbsolutePath(), 35);
	}

	public CommMsg signComponentMessage(CommMsg dataToSign, String sendingComponent) throws Exception {
		Certificate certificate = certificateReaderService.readCertificateFromFile(
				propertyService.getComponentCertificateFile(sendingComponent).getAbsolutePath()
		);
		File privateKeyFile = propertyService.getComponentSigningPrivateKeyFile(sendingComponent);
		// 35 is security management PSID
		Ieee1609Dot2Data dot2Data = signIntoDot2Data(dataToSign, certificate, privateKeyFile.getAbsolutePath(), 35);
		return asnEncoder.simpleEncode(dot2Data);
	}
}
