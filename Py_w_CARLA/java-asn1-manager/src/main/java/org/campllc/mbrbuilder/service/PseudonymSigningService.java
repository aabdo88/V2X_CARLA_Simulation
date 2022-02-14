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

import org.apache.commons.codec.binary.Hex;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PseudonymSigningService {
	public class PseudonymSigningResult {
		public String rSig;
		public String sSig;
		public String digest;
		public int yPoint;
	}

	@Autowired
	ASNEncoder asnEncoder;

	@Autowired
	private PythonRunner pythonRunner;

	@Autowired
	private CertificateReaderService certificateReaderService;

	public PseudonymSigningResult signPayload(byte[] tbs, String certDir, String certGroup, String certNumber, String pcaFile) {
		PseudonymSigningResult returnData = new PseudonymSigningResult();
		// read in the PCS cert
		CurvePoint certificateResult =  certificateReaderService.readCertificateVerificationKeyFromFile(pcaFile);
		// run the python script to get signature information
		ArrayList<String> arguments = new ArrayList<>();
		arguments.add("-f");
		arguments.add(certDir);
		arguments.add("-i");
		arguments.add(certGroup);
		arguments.add("-j");
		arguments.add(certNumber);
		arguments.add("--pcaFile");
		arguments.add(pcaFile);
		arguments.add("--pcaYPoint");
		arguments.add(Integer.toString(certificateResult.getyPoint()));
		arguments.add("-p");
		arguments.add(Hex.encodeHexString(certificateResult.getyValue()));
		arguments.add("-b");
		arguments.add(Hex.encodeHexString(tbs));
		String[] output = pythonRunner.runPythonScript("pseudonym_sign.py", arguments);
		returnData.rSig = output[0].substring(20,84);
		returnData.sSig = output[1].substring(2);
		returnData.digest = output[2];
		returnData.yPoint = certificateResult.getyPoint();
		return returnData;
	}
}
