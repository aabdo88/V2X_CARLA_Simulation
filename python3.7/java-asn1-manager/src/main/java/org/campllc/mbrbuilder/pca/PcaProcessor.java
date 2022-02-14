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
package org.campllc.mbrbuilder.pca;

import java.io.*;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.LinkageValue;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.MaPcaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.MaPcaPreLinkageValueRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.ToBeSignedMaPcaPreLinkageValueRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedMaPcaPreLinkageValueRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.pca.pojos.MaPcaPreLinkageValueRequest;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class PcaProcessor implements Processor {
	private static Log log = LogFactory.getLog(PcaProcessor.class);

	@Value("${pcaplv.outputPath}")
	String outPath;

	@Value("${pca.MaPcaFile}")
	String MaPcaFile;

	@Autowired
	private JSONReader reader;

	@Autowired
	private ASNEncoder asnEncoder;

	@Autowired
	private SigningService signingService;

	@Autowired
	private EncryptionService encryptionService;

	@Autowired
	private PropertyService propertyService;

	public PcaProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), PcaProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.sendPLVRequest;
	}

	@Override
	public void runProcess() {
		try {
			log.info("Beginning conversion and encryption for MaPcaPreLinkageValueRequest");

			InputStream input = new FileInputStream(propertyService.getControlFile());
			//create an MaPcaPreLinkageValueRequest and encode it into ASN
			MaPcaPreLinkageValueRequest requestMsg = reader.readMcPcaJSON(input);

			// build the basic object
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            ToBeSignedMaPcaPreLinkageValueRequestMsg.LinkageValues linkageValues = new ToBeSignedMaPcaPreLinkageValueRequestMsg.LinkageValues();
            for (String linkageValue : requestMsg.linkageValues) {
                linkageValues.add(new LinkageValue(Hex.decodeHex(linkageValue.toCharArray())));
            }
			ToBeSignedMaPcaPreLinkageValueRequestMsg.GroupLinkageValues groupLinkageValues = new ToBeSignedMaPcaPreLinkageValueRequestMsg.GroupLinkageValues();
            // TODO - fill in group linkage values if neeeded
            ToBeSignedMaPcaPreLinkageValueRequestMsg toBeSignedRequestMsg = new ToBeSignedMaPcaPreLinkageValueRequestMsg(maHostnameId,linkageValues, groupLinkageValues);
            // add the wrappers around it
            MaPcaPreLinkageValueRequestMsg.Signatures signatures = new MaPcaPreLinkageValueRequestMsg.Signatures();
            MaPcaPreLinkageValueRequestMsg maPcaPreLinkageValueRequestMsg = new MaPcaPreLinkageValueRequestMsg(
                    new Uint8(1), toBeSignedRequestMsg, signatures
            );

            MaPcaInterfacePDU maPcaInterfacePDU = MaPcaInterfacePDU.createMaPcaInterfacePDUWithMaPcaPreLinkageValueRequest(maPcaPreLinkageValueRequestMsg);
            ScmsPDU.Content content = ScmsPDU.Content.createContentWithMa_pca(maPcaInterfacePDU);
            ScopedMaPcaPreLinkageValueRequest scopedMaPcaPreLinkageValueRequest = new ScopedMaPcaPreLinkageValueRequest(
                new Uint8(1), content
            );

			// Should be equivalent to a SignedMaPcaPreLinkageValueRequest
			Ieee1609Dot2Data signedDot2Data = signingService.signComponentMessage(
					scopedMaPcaPreLinkageValueRequest, "ma"
			);
			CommMsg signedMessage = asnEncoder.simpleEncode(signedDot2Data);
			// write out the signed data so we can review it
			File outDirectory = new File(outPath);
			File signedFile = new File(outDirectory, "signed_" + MaPcaFile);
			log.info("Writing signed file: " + signedFile.getAbsolutePath());
			FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
			signedFileOutputStream.write(signedMessage.getMsg());
            // encrypted into SecuredMaPcaPreLinkageValueRequest
			Ieee1609Dot2Data encryptedDot2Data = encryptionService.encryptIntoDot2Data(signedMessage.toHex(),
					propertyService.getComponentCertificateFile("pca").getAbsolutePath());
			CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedDot2Data);
			File encryptedFile = new File(outDirectory, MaPcaFile);
			log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
			FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
			encryptedFileOutputStream.write(encryptedMessage.getMsg());

			log.info("Process complete");
		} catch (Exception e) {
			throw new RuntimeException("Unable to process PCA message", e);
		}
	}
}

