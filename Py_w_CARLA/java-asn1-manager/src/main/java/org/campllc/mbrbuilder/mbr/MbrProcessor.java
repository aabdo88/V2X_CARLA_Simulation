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
package org.campllc.mbrbuilder.mbr;

import java.io.*;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.oss.asn1.Null;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generatedmai.ieee1609dot2.*;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.*;
import org.campllc.asn1.generatedmai.ieee1609dot2endentitymainterface.*;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsprotocol.ScopedMisbehaviorReport;
import org.campllc.mbrbuilder.mbr.pojos.BSM;
import org.campllc.mbrbuilder.mbr.pojos.EvidenceData;
import org.campllc.mbrbuilder.mbr.pojos.VehicleWSMs;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.mbr.pojos.MBR;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.campllc.mbrbuilder.service.mai.ASNEncoderMAI;
import org.campllc.mbrbuilder.service.mai.CertificateReaderServiceMAI;
import org.campllc.mbrbuilder.service.mai.EncryptionServiceMAI;
import org.campllc.mbrbuilder.service.mai.PseudonymSigningServiceMAI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MbrProcessor implements Processor {
	private static Log log = LogFactory.getLog(MbrProcessor.class);

	@Value("${mbr.bsmDir}")
	String bsmDirectory;
	@Value("${mbr.outputPath:nopath}")
	String outPath;
	@Value("${mbr.mbrFile:nopath}")
	String mbrFile;

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private ASNEncoderMAI encoder;

	@Autowired
	private CertificateReaderServiceMAI certificateReaderService;

	@Autowired
	private PseudonymSigningServiceMAI signingService;

	@Autowired
	private EncryptionServiceMAI encryptionService;

	public MbrProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), MbrProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.mbr;
	}

	@Override
	public void runProcess() {
		try {
			log.info("Beginning conversion and encryption for MBR");

			//create an MBR and encode it into ASN
			InputStream input = new FileInputStream(propertyService.getControlFile());
			ObjectMapper mapper = new ObjectMapper();
			MBR mbr = mapper.readValue(input, MBR.class);

			EndEntityMaInterfacePDU eeMa = createEndEntityPDU(mbr);

			CommMsg unsigned = encoder.simpleEncode(eeMa);
			ScopedMisbehaviorReport scopedMbr = new ScopedMisbehaviorReport(new Uint8(1), ScmsPDU.Content.createContentWithEe_ma(eeMa));

			//convert to a signedMBR and print to file
			Ieee1609Dot2Data signedData = signingService.signAbstractDataIntoDot2Data(scopedMbr, 0x26, 1,
					getCertDirectoryForVehicle(mbr.getVehicleId()).getAbsolutePath(),
					mbr.getCertificateGroup(), mbr.getCertificateNumber());
			CommMsg signedMBR = encoder.simpleEncode(signedData);
			//convert to encrypted mbr (SecuredMisbehaviorReport) and write to file
			Ieee1609Dot2Data encryptedData = encryptionService.encryptIntoDot2Data(signedMBR.toHex(),
					propertyService.getComponentCertificateFile("ma").getAbsolutePath());
			CommMsg encryptedMBR = encoder.simpleEncode(encryptedData);
			FileOutputStream mbrOutputStream = new FileOutputStream(outPath + mbrFile);
			mbrOutputStream.write(encryptedMBR.getMsg());
			log.info("Process complete");
		} catch (Exception e) {
			throw new RuntimeException("Unable to create MBR", e);
		}
	}

	private File getCertDirectoryForVehicle(String vehicleId) {
		return vehicleService.getVehicleFile(
				vehicleId,VehicleService.CERTIFICATE_DIRECTORY);
	}

	private EndEntityMaInterfacePDU createEndEntityPDU(MBR mbrPojo) {
		MisbehaviorReport mbr= new MisbehaviorReport();
		Evidence[] evidence= new Evidence[mbrPojo.getEvidenceData().length];
		for (int i=0; i< mbrPojo.getEvidenceData().length;i++)
		{
			evidence[i] = createEvidenceASNObject(mbrPojo.getEvidenceData()[i]);
		}
		mbr.setEvidentiaryData(new MisbehaviorReport.EvidentiaryData(evidence));
		mbr.setPolicyFilename(new PolicyFilename(mbrPojo.getPolicyFilename()));
		if (mbrPojo.getReportType().equals("proximityPlausibility"))
		{
			mbr.setReportType(ReportType.createReportTypeWithProximityPlausibility(ProximityPlausibility.createProximityPlausibilityWith_default(Null.VALUE)));
		}
		else if (mbrPojo.getReportType().equals("warningReport"))
		{
			mbr.setReportType(ReportType.createReportTypeWithWarningReport(WarningReport.createWarningReportWith_default(Null.VALUE)));
		}
		else
		{
			throw new IllegalStateException("report type is invalid");
		}
		mbr.setVersion(new Uint8(mbrPojo.getVersion()));
		mbr.setGenerationTime(new Time32(mbrPojo.getGenerationTime()));
		return EndEntityMaInterfacePDU.createEndEntityMaInterfacePDUWithMisbehaviorReport(mbr);
	}

	private Evidence createEvidenceASNObject(EvidenceData evidenceData) {
		SignedBSMsWithCertificate[] asnNeighbors= new SignedBSMsWithCertificate[evidenceData.getObservedNeighborList().length];
		for (int i=0;i<evidenceData.getObservedNeighborList().length;i++)
		{
			asnNeighbors[i] = createSignedBSMs(evidenceData.getObservedNeighborList()[i]);
		}
		SignedBSM[] asnReporter= generateBSMs(evidenceData.getReporterWSMs());
		SignedBSMsWithCertificate[] asnSuspects= new SignedBSMsWithCertificate[evidenceData.getSuspectVehicleList().length];
		for (int i=0;i<evidenceData.getSuspectVehicleList().length;i++)
		{
			asnSuspects[i] = createSignedBSMs(evidenceData.getSuspectVehicleList()[i]);
		}
		Evidence.ObservedNeighborList neighbors= new Evidence.ObservedNeighborList(asnNeighbors);
		Evidence.SuspectVehicleList suspects= new Evidence.SuspectVehicleList(asnSuspects);
		Evidence.ReporterBSMs reporter= new Evidence.ReporterBSMs(asnReporter);
		Evidence out= new Evidence(neighbors,reporter,suspects);
		return out;
	}

	private SignedBSMsWithCertificate createSignedBSMs(VehicleWSMs vehicleWsms)
	{
		SignedBSMsWithCertificate.SignedBSMList bsmList=
				new SignedBSMsWithCertificate.SignedBSMList(generateBSMs(vehicleWsms));
		SignedBSMsWithCertificate out= new SignedBSMsWithCertificate();
		out.setSignedBSMList(bsmList);
		out.setSigningCertificate(createVehicleCertFromBytes(vehicleWsms));
		return out;
	}

	private ImplicitCertificate createVehicleCertFromBytes(VehicleWSMs vehicleWsms)
	{
		String downloadDirectory =
				new File(getCertDirectoryForVehicle(vehicleWsms.getVehicleId()),
						VehicleService.CERTIFICATE_DOWNLOAD_DIRECTORY).getAbsolutePath();
		File certGroupDirectory = new File(downloadDirectory, vehicleWsms.getCertificateGroup());
		File file= new File(certGroupDirectory,
				vehicleWsms.getCertificateGroup().toUpperCase()
				+ "_" + vehicleWsms.getCertificateNumber() + ".cert");
		Certificate cert = certificateReaderService.readCertificateFromFile(file.getAbsolutePath());
		ImplicitCertificate out = new ImplicitCertificate();
		out.setVersion(cert.getVersion());
		out.setIssuer(cert.getIssuer());
		out.setType(cert.getType());
		out.setToBeSigned(cert.getToBeSigned());
		return out;
	}

	private SignedBSM[] generateBSMs(VehicleWSMs vehicleWsms)
	{
		SignedBSM[] out=new SignedBSM[vehicleWsms.getBsmNumber().length];
		try {
			File file=new File(bsmDirectory + "/" + vehicleWsms.getBsmFile());
			InputStream inputStream = new FileInputStream(file);
			CsvSchema schema = CsvSchema.emptySchema()
					.withHeader()
					.withColumnSeparator(',');
			CsvMapper mapper = new CsvMapper();
			MappingIterator<BSM> iter = mapper.readerFor(BSM.class).with(schema).readValues(inputStream);
			int counter = 1;
			int numElements = 0;
			while (iter.hasNext() & numElements < out.length) {
				BSM bsm = iter.next();
				for (int i = 0; i < vehicleWsms.getBsmNumber().length; i++) {
					if (counter == vehicleWsms.getBsmNumber()[i]) {
						out[numElements] = createSignedBSM(bsm, vehicleWsms);
						numElements++;
					}
				}
				counter++;
			}
		}catch(Exception e)
		{
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		return out;
	}

	private SignedBSM createSignedBSM(BSM bsm, VehicleWSMs vehicleWsms) throws Exception {
		Ieee1609Dot2Data dot2Data =  signingService.signIntoDot2Data(new Opaque(Hex.decodeHex(bsm.getHexMessage().toCharArray())),
				0x20, vehicleWsms.getGenerationTimeOffset(),
				getCertDirectoryForVehicle(vehicleWsms.getVehicleId()).getAbsolutePath(),
				vehicleWsms.getCertificateGroup(), vehicleWsms.getCertificateNumber());

		return new SignedBSM(new Uint8(3),dot2Data.getContent());
	}

}
