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
package org.campllc.mbrbuilder.malalinkageseed;

import java.io.*;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Content;
import org.campllc.asn1.generated.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generated.ieee1609dot2basetypes.LinkageSeed;
import org.campllc.asn1.generated.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generated.ieee1609dot2lamainterface.MaLaLinkageSeedRequestMsg;
import org.campllc.asn1.generated.ieee1609dot2lamainterface.LaMaInterfacePDU;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.LinkageChainId;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.asn1.generated.ieee1609dot2scmsprotocol.ScopedLSRequest;
import org.campllc.asn1.generated.ieee1609dot2scmscomponentcertificatemanagement.CompositeCrl;
import org.campllc.asn1.generated.ieee1609dot2lamainterface.ToBeSignedLSRequestMsg;
import org.campllc.mbrbuilder.malalinkageseed.pojos.MaLaLinkageSeedRequest;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MaLaLinkageProcessor implements Processor{

    private static Log log = LogFactory.getLog(MaLaLinkageProcessor.class);

    @Value("${lals.outputpath}")
    String outPath;

    @Value("${la.maLaLinkageSeedRequestFile}")
    String maLaLinkageSeedRequestFile;

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

    public MaLaLinkageProcessor() {
        ProcessorManager.processorMap.put(getProcessorType(), MaLaLinkageProcessor.class);
    }

    @Override
    public ProcessingTypes getProcessorType() {
        return ProcessingTypes.sendLSRequest;
    }

    @Override
    public void runProcess() {
        try {
            log.info("Beginning conversion and encryption for MaLaLinkageSeedRequest");

            InputStream input = new FileInputStream(propertyService.getControlFile());
            //create an MaLaLinkageRequest and encode it into ASN
            MaLaLinkageSeedRequest requestMsg = reader.readMaLaLinkageSeedRequestJSON(input);

            // build the basic object
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            // Add LCI
            ToBeSignedLSRequestMsg.Lci lci = new ToBeSignedLSRequestMsg.Lci();
            ToBeSignedLSRequestMsg toBeSignedLSRequestMsg = new ToBeSignedLSRequestMsg(maHostnameId, lci);
            for (String linkageSeedValue : requestMsg.lci) {
                LinkageChainId linkageChainId = encryptionService.createLinkageChainId(linkageSeedValue.getBytes());
                System.out.println(linkageChainId);
                lci.add(linkageChainId);
            }
            MaLaLinkageSeedRequestMsg.Signatures signatures = new MaLaLinkageSeedRequestMsg.Signatures();
            MaLaLinkageSeedRequestMsg maLaLinkageSeedRequestMsg = new MaLaLinkageSeedRequestMsg(new Uint8(1),
                    toBeSignedLSRequestMsg, signatures);
            LaMaInterfacePDU laMaInterfacePDU = LaMaInterfacePDU.createLaMaInterfacePDUWithMaLaLinkageSeedRequest(maLaLinkageSeedRequestMsg);
            ScmsPDU.Content content =ScmsPDU.Content.createContentWithLa_ma(laMaInterfacePDU);
            ScopedLSRequest scopedLSRequest = new ScopedLSRequest(
                    new Uint8(1), content);

            // Should be equivalent to a MaLaLinkageSeedRequest
            Ieee1609Dot2Data signedDot2Data = signingService.signComponentMessage(
                    scopedLSRequest, "ma"
            );
            CommMsg signedMessage = asnEncoder.simpleEncode(signedDot2Data);
            // write out the signed data so we can review it
            File outDirectory = new File(outPath);
            File signedFile = new File(outDirectory, "signed_" + maLaLinkageSeedRequestFile);
            log.info("Writing signed file: " + signedFile.getAbsolutePath());
            FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
            signedFileOutputStream.write(signedMessage.getMsg());
            System.out.println("Writing signed MaLaLinkageValue message");
            System.out.println(signedMessage.toHex());
            // encrypted into MaLaLinkageSeedRequest
            Ieee1609Dot2Data encryptedDot2Data = encryptionService.encryptIntoDot2Data(signedMessage.toHex(),
                    propertyService.getComponentCertificateFile("la1").getAbsolutePath());
            CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedDot2Data);
            File encryptedFile = new File(outDirectory, maLaLinkageSeedRequestFile);
            log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
            FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
            encryptedFileOutputStream.write(encryptedMessage.getMsg());

            log.info("Process complete");
        } catch (Exception e) {
            throw new RuntimeException("Unable to process MaLaLinkageSeed message", e);
        }
    }
}
