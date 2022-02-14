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
package org.campllc.mbrbuilder.maracdv;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2marainterface.MaRaCDVRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2marainterface.MaRaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2marainterface.ToBeSignedCDVRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.RIF;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.mbrbuilder.maracdv.pojos.MaRaCDVRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

@Component
public class MaRaCdvProcessor implements Processor {
    private static Log log = LogFactory.getLog(MaRaCdvProcessor.class);

    @Value("${maraCDV.outputPath}")
    String outPath;

    @Value("${ra.CDVRequestFile}")
    String CDVRequestFile;

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

    public MaRaCdvProcessor() {
        ProcessorManager.processorMap.put(getProcessorType(), MaRaCdvProcessor.class);
    }

    @Override
    public ProcessingTypes getProcessorType() {
        return ProcessingTypes.sendCDVRequest;
    }

    @Override
    public void runProcess() {
        try {
            log.info("Beginning conversion and encryption for CDVRequest");

            InputStream input = new FileInputStream(propertyService.getControlFile());
            //create an ObeIdBlacklistRequest and encode it into ASN
            MaRaCDVRequest requestMsg = reader.readCDVRequestJSON(input);
            ToBeSignedCDVRequestMsg.RifValues rifValues = new ToBeSignedCDVRequestMsg.RifValues();
            for (String rifValue : requestMsg.rif) {
                rifValues.add(new RIF(Hex.decodeHex(rifValue.toCharArray())));
            }
            // build the basic object
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            ToBeSignedCDVRequestMsg toBeSignedCDVRequestMsg = new ToBeSignedCDVRequestMsg(
                    maHostnameId, rifValues
            );
            // add the wrappers around it
            MaRaCDVRequestMsg.Signatures signatures = new MaRaCDVRequestMsg.Signatures();
            MaRaCDVRequestMsg maRaCDVRequestMsg = new MaRaCDVRequestMsg( new Uint8(1),
                    toBeSignedCDVRequestMsg, signatures);

            MaRaInterfacePDU maRaInterfacePDU = MaRaInterfacePDU.createMaRaInterfacePDUWithMaRaCDVRequest(maRaCDVRequestMsg);
            ScmsPDU.Content content = ScmsPDU.Content.createContentWithMa_ra(maRaInterfacePDU);

            // Should be equivalent to a CDVRequest
            Ieee1609Dot2Data signedDot2Data = signingService.signComponentMessage(
                    maRaCDVRequestMsg, "ma"
            );
            CommMsg signedMessage = asnEncoder.simpleEncode(signedDot2Data);
            // write out the signed data so we can review it
            File outDirectory = new File(outPath);
            File signedFile = new File(outDirectory, "signed_" + CDVRequestFile);
            log.info("Writing signed file: " + signedFile.getAbsolutePath());
            FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
            signedFileOutputStream.write(signedMessage.getMsg());
            // encrypted into CDVRequest
            Ieee1609Dot2Data encryptedDot2Data = encryptionService.encryptIntoDot2Data(signedMessage.toHex(),
                    propertyService.getComponentCertificateFile("ra").getAbsolutePath());
            CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedDot2Data);
            File encryptedFile = new File(outDirectory, CDVRequestFile);
            log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
            FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
            encryptedFileOutputStream.write(encryptedMessage.getMsg());

            log.info("Process complete");
        } catch (Exception e) {
            throw new RuntimeException("Unable to process MaRaRseObeBlacklistRequest message", e);
        }
    }
}
