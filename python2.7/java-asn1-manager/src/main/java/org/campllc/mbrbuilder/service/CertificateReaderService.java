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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.campllc.asn1.generated.ieee1609dot2.Certificate;
import org.campllc.asn1.generated.ieee1609dot2basetypes.EccP256CurvePoint;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CertificateReaderService {

	@Autowired
	private ASNEncoder encoder;

	CurvePoint readCertificateVerificationKeyFromFile(String certFile) {
		CurvePoint certificateResult = new CurvePoint();
		try {
			InputStream inputStream = new FileInputStream(certFile);
			Certificate certificate = encoder.decodeCertificate(inputStream);
			EccP256CurvePoint curvePoint =	certificate.getToBeSigned().getVerifyKeyIndicator().getVerificationKey().getEcdsaNistP256();
			certificateResult.readFromEccP256CurvePoint(curvePoint);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return certificateResult;
	}

	public Certificate readCertificateFromFile(String fileName)  {
		try {
			InputStream inputStream = new FileInputStream(fileName);
			return encoder.decodeCertificate(inputStream);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public Certificate readPseudonymCertificate(String certificateDirectory, String certificateGroup, String certificateNumber) {
		File file = new File(certificateDirectory + "/download/" + certificateGroup
				+ "/" + certificateGroup.toUpperCase() + "_" + certificateNumber + ".cert");
		return  readCertificateFromFile(file.getAbsolutePath());
	}
}
