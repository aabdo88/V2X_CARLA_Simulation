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
package org.campllc.mbrbuilder.pseudonymdownload;

import java.io.FileInputStream;
import java.time.Instant;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oss.asn1.UTF8String16;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Certificate;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Time32;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.AuthenticatedDownloadRequest;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.EndEntityRaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.*;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.pseudonymdownload.pojos.PseudonymDownload;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PseudonymDownloadProcessor implements Processor {
	private static Log log = LogFactory.getLog(PseudonymDownloadProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private CertificateReaderService certificateReaderService;

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private TAITimeService timeService;

	@Autowired
	private SigningService signingService;

	@Autowired
	private EncryptionService encryptionService;

	public PseudonymDownloadProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), PseudonymDownloadProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.pseudonymDownload;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			PseudonymDownload pseudonymDownload = mapper.readValue(input, PseudonymDownload.class);

			String vehicleId = Hex.encodeHexString(vehicleService.loadVehicleFileData(
					pseudonymDownload.getVehicleId(), VehicleService.VEHICLE_HASH_FILE));

			// set up a loop for the number of periods to generate
			String iPeriodString = pseudonymDownload.getiPeriod();
			if (iPeriodString == null) {
				long iPeriod = timeService.getSCMSIPeriod(Instant.now());
				iPeriodString = Long.toHexString(iPeriod);
			}
			log.info("starting iPeriod: " + iPeriodString + " number of periods: " + pseudonymDownload.getNumberOfPeriods());

			for (int i = 0; i < pseudonymDownload.getNumberOfPeriods(); i++) {

				log.info("generating request for iPeriod: " + iPeriodString);
				// create the end entity object
				EndEntityRaInterfacePDU endEntityInterfacePDU = createDownloadRequestObject(vehicleId, iPeriodString);

				// complete the download object setup and encoding
				ScopedAuthenticatedDownloadRequest scopedAuthenticatedDownloadRequest = new ScopedAuthenticatedDownloadRequest(new Uint8(1),
						ScmsPDU.Content.createContentWithEe_ra(endEntityInterfacePDU));

				Certificate enrollmentCert = certificateReaderService.readCertificateFromFile(
						vehicleService.getVehicleFile(pseudonymDownload.getVehicleId(), VehicleService.ENROLLMENT_CERTIFICATE).getAbsolutePath()
				);
				// copy to another object since we do not have a hierarchy
				ScopedCertificateRequest scopedCertificateRequest = new ScopedCertificateRequest(
						scopedAuthenticatedDownloadRequest.getVersion(),
						scopedAuthenticatedDownloadRequest.getContent()
				);
				SignedCertificateRequest signedCertificateRequest = signingService.signCertificateRequest(
						scopedCertificateRequest, enrollmentCert,
						vehicleService.getVehicleFile(pseudonymDownload.getVehicleId(), VehicleService.ENROLLMENT_PRIVATE_KEY).getAbsolutePath()
				);
				SignedAuthenticatedDownloadRequest signedAuthenticatedDownloadRequest =
						new SignedAuthenticatedDownloadRequest(
								new Uint8(3),
								SignedAuthenticatedDownloadRequest.Content.createContentWithSignedCertificateRequest(
										new SignedAuthenticatedDownloadRequest.Content.SignedCertificateRequest(signedCertificateRequest))
						);

				log.info("Created signed download request");
				vehicleService.saveVehicleFileData(pseudonymDownload.getVehicleId(),
						VehicleService.DOWNLOAD_REQUEST_SIGNED,
						asnEncoder.simpleEncode(signedAuthenticatedDownloadRequest).getMsg());

				// encrypt using the RA certificate
				Ieee1609Dot2Data encryptedRequest = encryptionService.encryptIntoDot2Data(
						asnEncoder.simpleEncode(signedAuthenticatedDownloadRequest).toHex(),
						propertyService.getComponentCertificateFile("ra").getAbsolutePath());
				log.info("Created encrypted download request");

				String fileName = VehicleService.DOWNLOAD_REQUEST_SECURED_PREFIX + "-" + iPeriodString + ".oer";
				vehicleService.saveVehicleFileData(pseudonymDownload.getVehicleId(),
						fileName, asnEncoder.simpleEncode(encryptedRequest).getMsg());
				log.info("Secured download request created with file name: " + fileName);

				// set the next period number
				long periodNumericValue = Long.parseLong(iPeriodString,16);
				periodNumericValue ++;
				iPeriodString = Long.toHexString(periodNumericValue);
			}

		} catch (Exception e) {
			throw new RuntimeException("Unable to create pseudonym download", e);
		}
	}

	private EndEntityRaInterfacePDU createDownloadRequestObject(String vehicleId, String iPeriod) {
		String fileName = vehicleId + "_" + iPeriod + ".zip";
		AuthenticatedDownloadRequest downloadRequest = new AuthenticatedDownloadRequest(
				new Time32(timeService.now()), new UTF8String16(fileName.toUpperCase())
		);
		return EndEntityRaInterfacePDU.createEndEntityRaInterfacePDUWithEeRaAuthenticatedDownloadRequest(downloadRequest);
	}
}
