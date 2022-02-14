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
package org.campllc.mbrbuilder.decrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.mbrbuilder.decrypt.pojos.Decrypt;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.ASNEncoder;
import org.campllc.mbrbuilder.service.EncryptionService;
import org.campllc.mbrbuilder.service.PropertyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DecryptProcessor implements Processor {
	private static Log log = LogFactory.getLog(DecryptProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private EncryptionService encryptionService;

	@Autowired
	private ASNEncoder asnEncoder;

	public DecryptProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), DecryptProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.decrypt;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream controlInput = new FileInputStream(propertyService.getControlFile());
			Decrypt decrypt = mapper.readValue(controlInput, Decrypt.class);

			// create the Dot2Data Object
			byte[] inputBytes = Files.readAllBytes(Paths.get(decrypt.getInputFile()));
			Ieee1609Dot2Data dot2Data = asnEncoder.decodeIeeeData(new CommMsg(inputBytes));
			CommMsg outputMessage = encryptionService.decryptDot2Data(dot2Data,
					propertyService.getComponentCertificateFile(decrypt.getComponentType()),
					propertyService.getComponentEncryptionPrivateKeyFile(decrypt.getComponentType()) );
			FileOutputStream outputStream = new FileOutputStream(new File(decrypt.getOutputFile()));
			outputStream.write(outputMessage.getMsg());

		} catch (Exception e) {
			throw new RuntimeException("Unable to parse response file", e);
		}
	}
}
