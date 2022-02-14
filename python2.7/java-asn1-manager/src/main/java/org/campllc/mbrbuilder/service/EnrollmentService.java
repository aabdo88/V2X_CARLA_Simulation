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

import java.util.ArrayList;

import com.oss.asn1.Null;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.SignerIdentifier;
import org.campllc.asn1.generated.ieee1609dot2basetypes.*;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedCertificateRequest;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.SignedCertificateRequest;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.SignedEeEnrollmentCertRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EnrollmentService {
	private static Log log = LogFactory.getLog(EnrollmentService.class);

	@Autowired
	private PythonRunner pythonRunner;

	@Autowired
	private ASNEncoder asnEncoder;

	public class KeyGenerationResult {
		public String privateKey;
		public CurvePoint publicKeyCurvePoint;
	}

	public class SigningKeyCreationResult {
		public String enrollmentPrivateKey;
		public String verifyKeyPrivate;
		public CurvePoint verifyKeyPublic;
		public String respEncKeyPrivate;
		public CurvePoint respEncKeyPublic;
	}

	public KeyGenerationResult generateKeyPair() throws DecoderException {
		ArrayList<String> arguments = new ArrayList<>();
		String[] output = pythonRunner.runPythonScript("enrollment_keygen.py", arguments);

		KeyGenerationResult result = new KeyGenerationResult();
		result.privateKey = output[0];
		result.publicKeyCurvePoint = new CurvePoint();
		result.publicKeyCurvePoint.readFromPythonOutput(output[1]);
		return result;
	}

	public SignedEeEnrollmentCertRequest selfSignEnrollmentRequest(
			ScopedCertificateRequest scopedCertificateRequest, KeyGenerationResult keyGenerationResult) throws Exception
	{
		CommMsg encodedTbs = asnEncoder.simpleEncode(scopedCertificateRequest);
		ArrayList<String> arguments = new ArrayList<>();
		arguments.add("-d");
		arguments.add(encodedTbs.toHex());
		arguments.add("--privatekey");
		arguments.add(keyGenerationResult.privateKey);
		arguments.add("--publickey");
		arguments.add(Hex.encodeHexString(keyGenerationResult.publicKeyCurvePoint.getyValue()));
		arguments.add("-y");
		arguments.add(String.valueOf(keyGenerationResult.publicKeyCurvePoint.getyPoint()));
		String [] output = pythonRunner.runPythonScript("enrollment_selfsign.py", arguments);
		String rValue = output[0];
		String sValue = output[1];

		EccP256CurvePoint curvePoint = EccP256CurvePoint.createEccP256CurvePointWithX_only(
				new OctetString(Hex.decodeHex(rValue.toCharArray()))
		);
		EcdsaP256Signature ecdsaP256Signature = new EcdsaP256Signature(
				curvePoint, new OctetString(Hex.decodeHex(sValue.toCharArray()))
		);

		SignedCertificateRequest signedCertificateRequest = new SignedCertificateRequest(
				HashAlgorithm.sha256, scopedCertificateRequest,
				SignerIdentifier.createSignerIdentifierWithSelf(new Null()),
				Signature.createSignatureWithEcdsaNistP256Signature(ecdsaP256Signature)
		);

		SignedEeEnrollmentCertRequest signedRequest = new SignedEeEnrollmentCertRequest(
				new Uint8(3), SignedEeEnrollmentCertRequest.Content.createContentWithSignedCertificateRequest(
						new SignedEeEnrollmentCertRequest.Content.SignedCertificateRequest(signedCertificateRequest)
						)
		);
		return signedRequest;
	}

	public SigningKeyCreationResult createSigningKey(
			byte[] privateKeyReconstruction, byte[] enrollmentCertTbs, byte[] ecaCert, byte[] basePrivateKey) throws DecoderException {
		ArrayList<String> arguments = new ArrayList<>();
		arguments.add("-p");
		arguments.add(Hex.encodeHexString(privateKeyReconstruction));
		arguments.add("-t");
		arguments.add(Hex.encodeHexString(enrollmentCertTbs));
		arguments.add("-e");
		arguments.add(Hex.encodeHexString(ecaCert));
		arguments.add("-b");
		arguments.add(Hex.encodeHexString(basePrivateKey));
		String [] output = pythonRunner.runPythonScript("enrollment_createsignkey.py", arguments);

		SigningKeyCreationResult result = new SigningKeyCreationResult();
		result.enrollmentPrivateKey = output[0];
		result.verifyKeyPrivate = output[1];
		result.verifyKeyPublic = new CurvePoint();
		result.verifyKeyPublic.readFromPythonOutput(output[2]);
		result.respEncKeyPrivate = output[3];
		result.respEncKeyPublic = new CurvePoint();
		result.respEncKeyPublic.readFromPythonOutput(output[4]);
		return result;
	}
}
