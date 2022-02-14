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
package org.campllc.mbrbuilder.enrollment;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.time.Instant;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.*;
import org.campllc.asn1.generated.ieee1609dot2basetypes.*;
import org.campllc.asn1.generated.ieee1609dot2ecaendentityinterface.EcaEndEntityInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2ecaendentityinterface.EeEcaCertRequest;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedCertificateRequest;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.SignedEeEnrollmentCertRequest;
import org.campllc.mbrbuilder.enrollment.pojos.Enrollment;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EnrollmentProcessor implements Processor {
	private static Log log = LogFactory.getLog(EnrollmentProcessor.class);

	private EnrollmentService.KeyGenerationResult keyGenerationResult;

	private Enrollment enrollment;

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private EnrollmentService enrollmentService;

	@Autowired
	private TAITimeService timeService;

	@Autowired
	private ASNEncoder asnEncoder;

	public EnrollmentProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), EnrollmentProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.enrollment;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			enrollment = mapper.readValue(input, Enrollment.class);

			// create the vehicle directory inside the main vehicle area
			File vehicleDirectory = vehicleService.getVehicleDirectory(enrollment.getVehicleId());
			if (vehicleDirectory.exists()) {
				throw new RuntimeException("Vehicle directory " + vehicleDirectory.getAbsolutePath() + " already exists!");
			}
			if (!vehicleDirectory.mkdir()) {
				throw new RuntimeException("Cannot create vehicle directory " + vehicleDirectory.getAbsolutePath() + "!");
			}

			// create the object which also generates the private/public key info
			EcaEndEntityInterfacePDU endEntityInterfacePDU = createCertRequestObject();

			// save the key information
			vehicleService.saveVehicleFileData(enrollment.getVehicleId(),
					VehicleService.BASE_PRIVATE_KEY,
					Hex.decodeHex(keyGenerationResult.privateKey.toCharArray()));

			// complete the enrollment object setup and encoding
			ScopedCertificateRequest scopedCertificateRequest = new ScopedCertificateRequest(new Uint8(1),
					ScmsPDU.Content.createContentWithEca_ee(endEntityInterfacePDU));
			SignedEeEnrollmentCertRequest signedCertRequest =
					enrollmentService.selfSignEnrollmentRequest(scopedCertificateRequest, keyGenerationResult);
			CommMsg encodedData =  asnEncoder.simpleEncode(signedCertRequest);
			log.info("Encocded data: " + encodedData.toHex());

			// save the enrollment request file to the vehicle directory
			File enrollmentRequestFile = new File(vehicleDirectory.getAbsolutePath(), "enrollment_request.oer");
			FileOutputStream enrollmentRequestOutput = new FileOutputStream(enrollmentRequestFile.getPath());
			enrollmentRequestOutput.write(encodedData.getMsg());
		} catch (Exception e) {
			throw new RuntimeException("Unable to create enrollment", e);
		}
	}

	private EcaEndEntityInterfacePDU createCertRequestObject() throws DecoderException {
		keyGenerationResult = enrollmentService.generateKeyPair();
		log.info("privateKey="+ keyGenerationResult.privateKey);
		log.info("yPointUsed="+ keyGenerationResult.publicKeyCurvePoint.getyPoint());
		log.info("publicKey="+ Hex.encodeHexString(keyGenerationResult.publicKeyCurvePoint.getyValue()));

		String vehicleIdForCertificiate = enrollment.getVehicleId();
		if (vehicleIdForCertificiate.length() % 2 == 1) {
			vehicleIdForCertificiate = "0" + vehicleIdForCertificiate;
		}
		CertificateId certificateId = CertificateId.createCertificateIdWithBinaryId(
				new OctetString(Hex.decodeHex(vehicleIdForCertificiate.toCharArray())));
		int currentTime = timeService.now();
		Duration duration = Duration.createDurationWithYears(2); // default 5 years
		if (enrollment.getValidUntil() != null) {
			Instant validUntil = Instant.parse(enrollment.getValidUntil());
			java.time.Duration timeDuration = java.time.Duration.between(Instant.now(), validUntil);
			// convert days to 60 hours (~2.5 days)
			duration = Duration.createDurationWithSixtyHours((long)(timeDuration.toDays() / 2.5));
			log.info("Setting up enrollment to go through " + enrollment.getValidUntil() +
				" duration in 60 hours: " + duration.toString());
		}
		ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(currentTime), duration);
		EccP256CurvePoint curvePoint = keyGenerationResult.publicKeyCurvePoint.createEccP256CurvePoint();
		PublicVerificationKey verificationKey = PublicVerificationKey.createPublicVerificationKeyWithEcdsaNistP256(curvePoint);
		VerificationKeyIndicator verificationKeyIndicator = VerificationKeyIndicator.createVerificationKeyIndicatorWithVerificationKey(verificationKey);
		byte[] cracaId = new byte[3];
		cracaId[0] = 0;
		cracaId[1] = 1;
		cracaId[2] = 2;
		ToBeSignedCertificate toBeSignedCertificate = new ToBeSignedCertificate(
				certificateId, new HashedId3(cracaId), new CrlSeries(4), validityPeriod, verificationKeyIndicator);

		SequenceOfIdentifiedRegion identifiedRegion = new SequenceOfIdentifiedRegion();
		identifiedRegion.add(IdentifiedRegion.createIdentifiedRegionWithCountryOnly(840)); // US
		identifiedRegion.add(IdentifiedRegion.createIdentifiedRegionWithCountryOnly(124)); // Canada
		identifiedRegion.add(IdentifiedRegion.createIdentifiedRegionWithCountryOnly(484)); // Mexico
		GeographicRegion geographicRegion = GeographicRegion.createGeographicRegionWithIdentifiedRegion(identifiedRegion);
		toBeSignedCertificate.setRegion(geographicRegion);

		SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions = new SequenceOfPsidGroupPermissions();

		SequenceOfPsidSspRange sequenceOfPsidSspRange = new SequenceOfPsidSspRange();
		sequenceOfPsidSspRange.add(new PsidSspRange(new Psid(0x20))); // BSM
		sequenceOfPsidSspRange.add(new PsidSspRange(new Psid(0x26))); // Misbehavior reporting
		SubjectPermissions subjectPermissions = SubjectPermissions.createSubjectPermissionsWithExplicit(sequenceOfPsidSspRange);

		EndEntityType endEntityType = new EndEntityType();
		endEntityType.setBit(EndEntityType.enrol);
		PsidGroupPermissions psidGroupPermissions = new PsidGroupPermissions(subjectPermissions, 0, 0, endEntityType);
		sequenceOfPsidGroupPermissions.add(psidGroupPermissions);
		toBeSignedCertificate.setCertRequestPermissions(sequenceOfPsidGroupPermissions);

		EeEcaCertRequest certRequest = new EeEcaCertRequest(
				new Uint8(1), new Time32(currentTime), toBeSignedCertificate);

		return EcaEndEntityInterfacePDU.createEcaEndEntityInterfacePDUWithEeEcaCertRequest(certRequest);
	}
}
