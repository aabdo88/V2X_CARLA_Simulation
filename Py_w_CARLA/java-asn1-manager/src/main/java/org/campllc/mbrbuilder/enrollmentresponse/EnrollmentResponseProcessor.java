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
package org.campllc.mbrbuilder.enrollmentresponse;

import java.io.*;
import java.security.SecureRandom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Certificate;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Time32;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2ecaendentityinterface.EcaEeCertResponse;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.CommonProvisioningRequestFields;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.EeRaPseudonymCertProvisioningRequest;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.EndEntityRaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2endentityrainterface.UnsignedButterflyParams;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.*;
import org.campllc.mbrbuilder.enrollmentresponse.pojos.EnrollmentResponse;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EnrollmentResponseProcessor implements Processor {
	private static Log log = LogFactory.getLog(EnrollmentResponseProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private EnrollmentService enrollmentService;

	@Autowired
	private TAITimeService timeService;

	@Autowired
	private SigningService signingService;

	@Autowired
	private EncryptionService encryptionService;

	private EnrollmentResponse enrollmentResponse;

	public EnrollmentResponseProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), EnrollmentResponseProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.enrollmentResponse;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			enrollmentResponse = mapper.readValue(input, EnrollmentResponse.class);

			// check to see that we have not already processed a response
			File enollmentPrivateKeyFile = vehicleService.getVehicleFile(enrollmentResponse.getVehicleId(),
					VehicleService.ENROLLMENT_PRIVATE_KEY);
			if (enollmentPrivateKeyFile.isFile()) {
				throw new RuntimeException("Enrollment private key file "
						+ enollmentPrivateKeyFile.getAbsolutePath()
						+ " already exists so enrollment response has already been processed and cannot be run again on the same vehicle!");
			}

			// read in the Enrollment Response from the vehicle directory
			byte[] enrollmentResponseData = vehicleService.loadVehicleFileData(
					enrollmentResponse.getVehicleId(), VehicleService.ENROLLMENT_REQUEST_RESPONSE);

			// decode the ASN data
			SignedEeEnrollmentCertResponse signedCertificateResponse = asnEncoder.decodeCertificateResponse(enrollmentResponseData);
			EcaEeCertResponse certificateResponse = signedCertificateResponse.getContent().getSignedData().getTbsData()
					.getPayload().getData().getContent().getUnsecuredData().getContainedValue()
					.getContent().getEca_ee().getEcaEeCertResponse();
			log.info("Decoded object");

			// get the private signing key for enrollment
			byte[] privateKeyReconstruction = certificateResponse.getPrivKeyReconstruction().byteArrayValue();
			byte[] enrollmentCertTbs = asnEncoder.simpleEncode(certificateResponse.getEnrollmentCert().getToBeSigned()).getMsg();
			byte[] ecaCert = asnEncoder.simpleEncode(certificateResponse.getEcaCert()).getMsg();
			byte[] basePrivateKey = vehicleService.loadVehicleFileData(
					enrollmentResponse.getVehicleId(), VehicleService.BASE_PRIVATE_KEY );
			EnrollmentService.SigningKeyCreationResult signingKeyCreationResult = enrollmentService.createSigningKey(
					privateKeyReconstruction, enrollmentCertTbs, ecaCert, basePrivateKey);

			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.ENROLLMENT_PRIVATE_KEY,
					Hex.decodeHex(signingKeyCreationResult.enrollmentPrivateKey.toCharArray()));
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.RESP_ENC_PRIVATE_KEY,
					Hex.decodeHex(signingKeyCreationResult.respEncKeyPrivate.toCharArray()));
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.VERIFY_PRIVATE_KEY,
					Hex.decodeHex(signingKeyCreationResult.verifyKeyPrivate.toCharArray()));

			log.info("Created enrollment signing key");

			// create provisioning request
			EndEntityRaInterfacePDU endEntityRaInterfacePDU = createProvisioningRequest(signingKeyCreationResult);
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.RESP_ENC_EXPANSION_KEY,
					endEntityRaInterfacePDU.getEeRaPseudonymCertProvisioningRequest().getResp_enc_key_info().getExpansion().byteArrayValue());
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.VERIFY_EXPANSION_KEY,
					endEntityRaInterfacePDU.getEeRaPseudonymCertProvisioningRequest().getVerify_key_info().getExpansion().byteArrayValue());
			log.info("Created base provisioning request");

			// create the enrollment certificate object
			Certificate enrollmentCert = new Certificate(
					certificateResponse.getEnrollmentCert().getVersion(),
					certificateResponse.getEnrollmentCert().getType(),
					certificateResponse.getEnrollmentCert().getIssuer(),
					certificateResponse.getEnrollmentCert().getToBeSigned(),
					certificateResponse.getEnrollmentCert().getSignature()
			);
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.ENROLLMENT_CERTIFICATE,
					asnEncoder.simpleEncode(enrollmentCert).getMsg());
			ScopedCertificateRequest scopedCertificateRequest = new ScopedCertificateRequest(
					new Uint8(1), ScmsPDU.Content.createContentWithEe_ra(endEntityRaInterfacePDU)
			);
			SignedCertificateRequest signedCertificateRequest = signingService.signCertificateRequest(
					scopedCertificateRequest, enrollmentCert,
					vehicleService.getVehicleFile(enrollmentResponse.getVehicleId(), VehicleService.ENROLLMENT_PRIVATE_KEY).getAbsolutePath()
			);
			SignedPseudonymCertProvisioningRequest signedPseudonymCertProvisioningRequest =
					new SignedPseudonymCertProvisioningRequest(
							new Uint8(3),
							SignedPseudonymCertProvisioningRequest.Content.createContentWithSignedCertificateRequest(
									new SignedPseudonymCertProvisioningRequest.Content.SignedCertificateRequest(signedCertificateRequest))
					);
			log.info("Created signed provisioning request");
			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.PROVISIONING_REQUEST_SIGNED,
					asnEncoder.simpleEncode(signedPseudonymCertProvisioningRequest).getMsg());

			// encrypt using the RA certificate
			Ieee1609Dot2Data encryptedRequest = encryptionService.encryptIntoDot2Data(
					asnEncoder.simpleEncode(signedPseudonymCertProvisioningRequest).toHex(),
					propertyService.getComponentCertificateFile("ra").getAbsolutePath());
			log.info("Created encrypted provisioning request");

			vehicleService.saveVehicleFileData(enrollmentResponse.getVehicleId(),
					VehicleService.PROVISIONING_REQUEST_SECURED,
					asnEncoder.simpleEncode(encryptedRequest).getMsg());

		} catch (Exception e) {
			throw new RuntimeException("Unable to handle enrollment response", e);
		}
	}

	private UnsignedButterflyParams createButterflyParams(CurvePoint curvePoint) throws DecoderException {
		SecureRandom random = new SecureRandom();
		byte[] expansionKeyBytes = new byte[16];
		random.nextBytes(expansionKeyBytes);
		return new UnsignedButterflyParams(curvePoint.createEccP256CurvePoint(),
				new OctetString(expansionKeyBytes));
	}

	private EndEntityRaInterfacePDU createProvisioningRequest(EnrollmentService.SigningKeyCreationResult signingKeyCreationResult) throws DecoderException {
		UnsignedButterflyParams verifyKeyInfo = createButterflyParams(signingKeyCreationResult.verifyKeyPublic );
		UnsignedButterflyParams respEncKeyInfo = createButterflyParams(signingKeyCreationResult.respEncKeyPublic);
		CommonProvisioningRequestFields common = new CommonProvisioningRequestFields(new Time32(timeService.now()), new Time32(timeService.now()));
		EeRaPseudonymCertProvisioningRequest pseudonymCertProvisioningRequest = new EeRaPseudonymCertProvisioningRequest(
				new Uint8(1), verifyKeyInfo, respEncKeyInfo, common
		);
		return EndEntityRaInterfacePDU.createEndEntityRaInterfacePDUWithEeRaPseudonymCertProvisioningRequest(pseudonymCertProvisioningRequest);
	}

}
