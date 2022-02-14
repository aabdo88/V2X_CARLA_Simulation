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
package org.campllc.mbrbuilder.marablacklist;

import java.io.*;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2marainterface.MaRaBlacklistRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2marainterface.MaRaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2marainterface.ToBeSignedBlacklistingInstructionMsg;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.HPCR;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedBlacklistRequest;
import org.campllc.mbrbuilder.marablacklist.pojos.MaRaBlacklistRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MaRaBlacklistProcessor implements Processor{

    private static Log log = LogFactory.getLog(MaRaBlacklistProcessor.class);

    @Value("${maRaBlacklistRequest.outputPath}")
    String outPath;

    @Value("${ra.maRaBlacklistRequestFile}")
    String BlacklistRequestFile;

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

    public MaRaBlacklistProcessor() {
        ProcessorManager.processorMap.put(getProcessorType(), MaRaBlacklistProcessor.class);
    }

    @Override
    public ProcessingTypes getProcessorType() {
        return ProcessingTypes.blacklistRequest;
    }

    @Override
    public void runProcess() {
        try {
            log.info("Beginning conversion and encryption for MaRaBlacklistRequest");

            InputStream input = new FileInputStream(propertyService.getControlFile());
            //create an MaRaBlacklistRequest and encode it into ASN
            MaRaBlacklistRequest requestMsg = reader.readMaRaBlacklistRequestJSON(input);
            ToBeSignedBlacklistingInstructionMsg.Hpcr hpcrValues = new ToBeSignedBlacklistingInstructionMsg.Hpcr();

            for (String hpcrValue : requestMsg.hpcr) {
                hpcrValues.add(new HPCR(Hex.decodeHex(hpcrValue.toCharArray())));
            }
            // build the basic object
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            ToBeSignedBlacklistingInstructionMsg toBeSignedBlacklistingInstructionMsg = new ToBeSignedBlacklistingInstructionMsg(
                    maHostnameId, hpcrValues
            );
            // add the wrappers around it
            MaRaBlacklistRequestMsg.Signatures signatures = new MaRaBlacklistRequestMsg.Signatures();
            MaRaBlacklistRequestMsg maRaBlacklistRequestMsg = new MaRaBlacklistRequestMsg( new Uint8(1),
                    toBeSignedBlacklistingInstructionMsg, signatures);

            MaRaInterfacePDU maRaInterfacePDU = MaRaInterfacePDU.createMaRaInterfacePDUWithMaRaBlacklistRequest(maRaBlacklistRequestMsg);
            ScmsPDU.Content content = ScmsPDU.Content.createContentWithMa_ra(maRaInterfacePDU);
            ScopedBlacklistRequest scopedBlacklistRequest = new ScopedBlacklistRequest(new Uint8(1),content);

            // Should be equivalent to a ScopedBlacklistRequest
            Ieee1609Dot2Data signedDot2Data = signingService.signComponentMessage(
                    scopedBlacklistRequest, "ma"
            );
            CommMsg signedMessage = asnEncoder.simpleEncode(signedDot2Data);
            // write out the signed data so we can review it
            File outDirectory = new File(outPath);
            File signedFile = new File(outDirectory, "signed_" + BlacklistRequestFile);
            log.info("Writing signed file: " + signedFile.getAbsolutePath());
            FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
            signedFileOutputStream.write(signedMessage.getMsg());
            // encrypted into MaRaBlacklistRequest
            Ieee1609Dot2Data encryptedDot2Data = encryptionService.encryptIntoDot2Data(signedMessage.toHex(),
                    propertyService.getComponentCertificateFile("ra").getAbsolutePath());
            CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedDot2Data);
            File encryptedFile = new File(outDirectory, BlacklistRequestFile);
            log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
            FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
            encryptedFileOutputStream.write(encryptedMessage.getMsg());

            log.info("Process complete");
        } catch (Exception e) {
            throw new RuntimeException("Unable to process MaRaBlacklistRequest message", e);
        }
    }
}
