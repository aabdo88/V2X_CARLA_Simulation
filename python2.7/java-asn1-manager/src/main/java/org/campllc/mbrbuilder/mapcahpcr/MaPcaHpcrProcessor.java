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
package org.campllc.mbrbuilder.mapcahpcr;

import java.io.*;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.LinkageValue;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.MaPcaHPCRRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.MaPcaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2mapcainterface.ToBeSignedMaPcaHPCRRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedMaPcaHPCRRequest;
import org.campllc.mbrbuilder.mapcahpcr.pojos.MaPcaHpcrRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MaPcaHpcrProcessor implements Processor {

    private static Log log = LogFactory.getLog(MaPcaHpcrProcessor.class);

    @Value("${pcahpcr.outputPath}")
    String outPath;

    @Value("${pca.MaPcaHpcrFile}")
    String MaPcaHpcrFile;

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

    public MaPcaHpcrProcessor() {
        ProcessorManager.processorMap.put(getProcessorType(), MaPcaHpcrProcessor.class);
    }

    @Override
    public ProcessingTypes getProcessorType() {
        return ProcessingTypes.sendHPCRRequest;
    }

    @Override
    public void runProcess() {
        try {
            log.info("Beginning conversion and encryption for MaPcaHpcrRequest");

            InputStream input = new FileInputStream(propertyService.getControlFile());
            //create an MaPcaHpcrRequest and encode it into ASN
            MaPcaHpcrRequest requestMsg = reader.readMaPcaHpcrJSON(input);

            // build the basic object
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            ToBeSignedMaPcaHPCRRequestMsg.Linkage_values linkageValues = new ToBeSignedMaPcaHPCRRequestMsg.Linkage_values();

            for (String linkageValue : requestMsg.linkageValues) {
                linkageValues.add(new LinkageValue(Hex.decodeHex(linkageValue.toCharArray())));
            }

            ToBeSignedMaPcaHPCRRequestMsg toBeSignedMaPcaHPCRRequestMsg = new ToBeSignedMaPcaHPCRRequestMsg(maHostnameId, linkageValues);

            // add the wrappers around it
            MaPcaHPCRRequestMsg.Signatures signatures = new MaPcaHPCRRequestMsg.Signatures();
            MaPcaHPCRRequestMsg maPcaHPCRRequestMsg = new MaPcaHPCRRequestMsg(new Uint8(1),
                    toBeSignedMaPcaHPCRRequestMsg, signatures);
            MaPcaInterfacePDU maPcaInterfacePDU = MaPcaInterfacePDU.createMaPcaInterfacePDUWithMaPcaHPCRRequest(maPcaHPCRRequestMsg);
            ScmsPDU.Content content =ScmsPDU.Content.createContentWithMa_pca(maPcaInterfacePDU);
            ScopedMaPcaHPCRRequest scopedMaPcaHPCRRequest = new ScopedMaPcaHPCRRequest(
                    new Uint8(1), content);

            // Should be equivalent to a ScopedMaPcaHPCRRequest
            Ieee1609Dot2Data signedDot2Data = signingService.signComponentMessage(
                    scopedMaPcaHPCRRequest, "ma"
            );
            CommMsg signedMessage = asnEncoder.simpleEncode(signedDot2Data);
            // write out the signed data so we can review it
            File outDirectory = new File(outPath);
            File signedFile = new File(outDirectory, "signed_" + MaPcaHpcrFile);
            log.info("Writing signed file: " + signedFile.getAbsolutePath());
            FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
            signedFileOutputStream.write(signedMessage.getMsg());
            // encrypted into MaPcaHPCRRequest
            Ieee1609Dot2Data encryptedDot2Data = encryptionService.encryptIntoDot2Data(signedMessage.toHex(),
                    propertyService.getComponentCertificateFile("pca").getAbsolutePath());
            CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedDot2Data);
            File encryptedFile = new File(outDirectory, MaPcaHpcrFile);
            log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
            FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
            encryptedFileOutputStream.write(encryptedMessage.getMsg());

            log.info("Process complete");
        } catch (Exception e) {
            throw new RuntimeException("Unable to process MaPcaHpcr message", e);
        }
    }

}
