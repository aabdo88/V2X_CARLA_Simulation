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
package org.campllc.mbrbuilder.provisioningack;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Calendar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.RaEePseudonymCertProvisioningAck;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.SignedPseudonymCertProvisioningAck;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.provisioningack.pojos.ProvisioningAcknowledgement;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ProvisioningAckProcessor implements Processor {
	private static Log log = LogFactory.getLog(ProvisioningAckProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private TAITimeService timeService;

	public ProvisioningAckProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), ProvisioningAckProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.provisioningAck;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			ProvisioningAcknowledgement provisioningAcknowledgement = mapper.readValue(input, ProvisioningAcknowledgement.class);

			// read in the provisioning ack from the vehicle directory
			byte[] provisioningAckData = vehicleService.loadVehicleFileData(
					provisioningAcknowledgement.getVehicleId(),
					VehicleService.PSEUDONYM_CERT_PROVISIONING_ACK);

			// decode the ASN data
			SignedPseudonymCertProvisioningAck provisioningAckContainer = asnEncoder.decodeProvisioningAck(provisioningAckData);
			RaEePseudonymCertProvisioningAck provisioningAck = provisioningAckContainer.getContent().getSignedData().getTbsData()
					.getPayload().getData().getContent().getUnsecuredData().getContainedValue()
					.getContent().getEe_ra().getRaEePseudonymCertProvisioningAck();
			log.info("Decoded object");

			log.info("Vehicle hash: " + Hex.encodeHexString(provisioningAck.getRequestHash().byteArrayValue()));
			Instant downloadTime = timeService.instantFromTAI(provisioningAck.getReply().getAck().getCertDLTime().longValue());
			log.info(" Download time: " + DateTimeFormatter.ofLocalizedDateTime(	FormatStyle.FULL)
					.withZone(Calendar.getInstance().getTimeZone().toZoneId()).format(downloadTime));
			log.info(" Url: " + provisioningAck.getReply().getAck().getCertDLURL().stringValue());

			vehicleService.saveVehicleFileData(provisioningAcknowledgement.getVehicleId(),
					VehicleService.VEHICLE_HASH_FILE, provisioningAck.getRequestHash().byteArrayValue()
					);

		} catch (Exception e) {
			throw new RuntimeException("Unable to handle provisioning acknowledgement", e);
		}
	}
}
