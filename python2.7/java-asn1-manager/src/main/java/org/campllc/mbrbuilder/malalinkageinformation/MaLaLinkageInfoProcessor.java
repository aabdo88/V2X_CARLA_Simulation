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
package org.campllc.mbrbuilder.malalinkageinformation;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generatedmai.ieee1609dot2.EncryptedData;
import org.campllc.asn1.generatedmai.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.IValue;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.LaId;
import org.campllc.asn1.generatedmai.ieee1609dot2basetypes.Uint8;
import org.campllc.asn1.generatedmai.ieee1609dot2lamainterface.LaMaInterfacePDU;
import org.campllc.asn1.generatedmai.ieee1609dot2lamainterface.MaLaLinkageInfoRequestMsg;
import org.campllc.asn1.generatedmai.ieee1609dot2lamainterface.ToBeSignedLIRequestMsg;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.EncryptedIndividualPLV;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.MaHostnameId;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.PreLinkageValue;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.ToBeEncryptedIndividualPLV;
import org.campllc.asn1.generatedmai.ieee1609dot2lamainterface.EncryptedPrelinkageValuePair;

import org.campllc.asn1.generatedmai.ieee1609dot2scmsprotocol.ScmsPDU;
import org.campllc.mbrbuilder.malalinkageinformation.pojos.MaLaLinkageInformationRequest;
import org.campllc.mbrbuilder.malalinkageinformation.pojos.PlvPair;
import org.campllc.asn1.generatedmai.ieee1609dot2scmsprotocol.ScopedLIRequest;
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
public class MaLaLinkageInfoProcessor implements Processor {

    private static Log log = LogFactory.getLog(MaLaLinkageInfoProcessor.class);

    @Value("${lali.outputPath}")
    String outPath;

    @Value("${la.maLaLinkageInformationRequestFile}")
    String maLaLinkageInformationRequestFile;

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

    public MaLaLinkageInfoProcessor() {
        ProcessorManager.processorMap.put(getProcessorType(), MaLaLinkageInfoProcessor.class);
    }

    @Override
    public ProcessingTypes getProcessorType() {
        return ProcessingTypes.sendLIRequest;
    }

    @Override
    public void runProcess() {
        try {
            log.info("Beginning conversion and encryption for MaLaLinkageInformationRequest");

            InputStream input = new FileInputStream(propertyService.getControlFile());
            MaLaLinkageInformationRequest requestMsg = reader.readMaLaLinkageInformationRequestJSON(input);
            MaHostnameId maHostnameId = new MaHostnameId(requestMsg.getMaID());
            ToBeSignedLIRequestMsg toBeSignedLIRequestMsg = new ToBeSignedLIRequestMsg();
            toBeSignedLIRequestMsg.setMaId(maHostnameId);
            for (PlvPair plvToBeEncrypted :requestMsg.toBeEncryptedPreLinkageValues){
                LaId laId = new LaId(plvToBeEncrypted.getLaID().getBytes());
                ToBeSignedLIRequestMsg.EncryptedPLVPair encryptedPrelinkageValuePair = new ToBeSignedLIRequestMsg.EncryptedPLVPair();
                EncryptedIndividualPLV suspectPLV = new EncryptedIndividualPLV();
                EncryptedIndividualPLV reporterPLV = new EncryptedIndividualPLV();
                suspectPLV.setVersion(new Uint8(1));
                suspectPLV.setLaId(laId);
                reporterPLV.setVersion(new Uint8(1));
                reporterPLV.setLaId(laId);
                ToBeEncryptedIndividualPLV suspectIndividualPLV = new ToBeEncryptedIndividualPLV();
                ToBeEncryptedIndividualPLV reporterIndividualPLV = new ToBeEncryptedIndividualPLV();
                reporterIndividualPLV.setIValue(new IValue(plvToBeEncrypted.getIvalue()));
                suspectIndividualPLV.setIValue(new IValue(plvToBeEncrypted.getIvalue()));
                suspectIndividualPLV.setPlv(new PreLinkageValue(Hex.decodeHex(plvToBeEncrypted.getSuspectPlv().toCharArray())));
                reporterIndividualPLV.setPlv(new PreLinkageValue(Hex.decodeHex(plvToBeEncrypted.getReporterPlv().toCharArray())));
                EncryptedData suspectEncPlv = encryptionService.createEncryptedPLV(suspectIndividualPLV);
                EncryptedData reporterEncPlv = encryptionService.createEncryptedPLV(reporterIndividualPLV);
                CommMsg commMsg = asnEncoder.simpleEncode(suspectEncPlv);
                suspectPLV.setEnc_plv(suspectEncPlv);
                reporterPLV.setEnc_plv(reporterEncPlv);
                EncryptedPrelinkageValuePair encryptedPLVPair = new EncryptedPrelinkageValuePair();
                encryptedPLVPair.setReporterEncryptedPLV(reporterPLV);
                encryptedPLVPair.setSuspectEncryptedPLV(suspectPLV);
                encryptedPrelinkageValuePair.add(encryptedPLVPair);
                CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedPrelinkageValuePair);
                File file = new File("EncryptedPrelinkageValuePair.oer");
                toBeSignedLIRequestMsg.setEncryptedPLVPair(encryptedPrelinkageValuePair);
                FileOutputStream encryptedFileOutputStream = new FileOutputStream(file);
                encryptedFileOutputStream.write(encryptedMessage.getMsg());
            }
            // add the wrappers around
            MaLaLinkageInfoRequestMsg.Signatures signatures = new MaLaLinkageInfoRequestMsg.Signatures();
            MaLaLinkageInfoRequestMsg maLaLinkageInfoRequestMsg = new MaLaLinkageInfoRequestMsg(new Uint8(1), toBeSignedLIRequestMsg, signatures);
            LaMaInterfacePDU laMaInterfacePDU = LaMaInterfacePDU.createLaMaInterfacePDUWithMaLaLinkageInfoRequest(maLaLinkageInfoRequestMsg);
            ScmsPDU.Content content =ScmsPDU.Content.createContentWithLa_ma(laMaInterfacePDU);
            ScopedLIRequest scopedLIRequest = new ScopedLIRequest(
                    new Uint8(1), content);
            CommMsg scopedLIRequestCommMessage = asnEncoder.simpleEncode(scopedLIRequest);
            CommMsg signedLIRequestCommMessage = signingService.signComponentMessage(scopedLIRequestCommMessage,"ma");
            // Should be equivalent to a MaLaLinkageInformationRequest
            // write out the signed data so we can review it
            File outDirectory = new File(outPath);
            File signedFile = new File(outDirectory, "signed_" + maLaLinkageInformationRequestFile);
            log.info("Writing signed file: " + signedFile.getAbsolutePath());
            FileOutputStream signedFileOutputStream = new FileOutputStream(signedFile);
            signedFileOutputStream.write(signedLIRequestCommMessage.getMsg());
            // encrypted into MaLaLinkageInformationRequest
            CommMsg encryptedMessage = encryptionService.encryptIntoDot2DataBytes(signedLIRequestCommMessage.toHex(),propertyService.getComponentCertificateFile("la1").getAbsolutePath());
            File encryptedFile = new File(outDirectory, maLaLinkageInformationRequestFile);
            log.info("Writing encrypted file: " + encryptedFile.getAbsolutePath());
            FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
            encryptedFileOutputStream.write(encryptedMessage.getMsg());

            log.info("Process complete");
        } catch (Exception e) {
            throw new RuntimeException("Unable to process MaLaLinkageInformation message", e);
        }
    }
}
