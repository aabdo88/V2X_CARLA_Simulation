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
package org.campllc.mbrbuilder.certificatechain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Certificate;
import org.campllc.asn1.generated.ieee1609dot2_cert_chains.CertificateStore;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedLocalCertificateChainFile;
import org.campllc.mbrbuilder.certificatechain.pojos.CertificateChain;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CertificateChainProcessor implements Processor {
	private static Log log = LogFactory.getLog(CertificateChainProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private ASNEncoder asnEncoder;

	public CertificateChainProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), CertificateChainProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.certificateChain;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			CertificateChain certificateChain = mapper.readValue(input, CertificateChain.class);

			File componentCertificateDirectory = propertyService.getComponentCertificateDirectory();;
			File certificateChainFile = new File(componentCertificateDirectory, certificateChain.getFileName());
			byte[] asnDataBytes = Files.readAllBytes(Paths.get(certificateChainFile.getAbsolutePath()));
			ScopedLocalCertificateChainFile certificateChainObject = asnEncoder.decodeCertificateChainFile(asnDataBytes);

			log.info("Read certificate chain file: " + certificateChainFile.toString());

			CertificateStore.Certs certs = certificateChainObject.getContent().getCert_chain()
					.getLocalCertificateChainFile().getRequiredCertStore().getCerts();
			for (Certificate certificate : certs.asCollection()) {
				saveCertificateFile(certificate, componentCertificateDirectory);
			}
			// save the MA cert separately
			saveCertificateFile(certificateChainObject.getContent().getCert_chain()
							.getLocalCertificateChainFile().getRequiredCertStore().getMaCertificate(),
					componentCertificateDirectory);

		} catch (Exception e) {
			throw new RuntimeException("Unable to parse response file", e);
		}
	}

	private void saveCertificateFile(Certificate certificate, File certificateDirectoryFile) throws Exception {
		String hostName = certificate.getToBeSigned().getId().getName().stringValue();
		String componentId = hostName.split("\\.")[0];
		log .info("Found cert for component: " + componentId);
		File certificateFileName = new File(certificateDirectoryFile,
				componentId + propertyService.getComponentCertificateType() + ".cert");
		byte[] certificateBytes = asnEncoder.simpleEncode(certificate).getMsg();
		FileOutputStream enrollmentRequestOutput = new FileOutputStream(certificateFileName.getPath());
		enrollmentRequestOutput.write(certificateBytes);
	}
}
